# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""OpenShell CredentialDriver gRPC service backed by Delinea Secret Server.

The driver holds two kinds of provider credentials:

* Stored: a value passed to `openshell provider create` becomes one Secret
  Server secret in the driver's folder. The handle is `v1:<secret id>`, and
  every read, update and delete re-checks that the secret behind it still
  carries the managed name derived from the identity the gateway presents.
* Attached: a value of `secretserver:<id>[/<field slug>]` points at a secret
  someone else owns, and nothing is copied. The handle is `ref1:<id>/<slug>`.
  The secret must sit in a folder listed in reference_folder_ids, the driver
  never writes to it, and deleting the provider only detaches it.

Every read carries an audit comment naming the provider, credential key and
workspace, so Secret Server's audit trail shows what each read was for.
"""

import logging
import re
from typing import Any, Dict, Optional, Tuple

import grpc

from . import __version__
from ._proto import credential_driver_pb2 as pb
from ._proto import credential_driver_pb2_grpc as pb_grpc
from ._proto import datamodel_pb2, extension_pb2
from .config import SLUG_PATTERN, DriverConfig
from .naming import managed_secret_name, reference_binding, requested_object_id
from .secret_server import SecretServerClient, SecretServerError

log = logging.getLogger("ss_driver.service")

DRIVER_NAME = "delinea-secret-server"
IMPLEMENTATION_NAME = "delinea/secret-server-credential-driver"
CONTRACT_CAPABILITY = "openshell.credentials.contract"
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
HANDLE_PREFIX = "v1:"
REFERENCE_HANDLE_PREFIX = "ref1:"
REFERENCE_PREFIX = "secretserver:"
OBJECT_ID_METADATA_KEY = "object_id"
BINDING_METADATA_KEY = "binding"
_REFERENCE = re.compile(rf"secretserver:([1-9][0-9]{{0,9}})(?:/({SLUG_PATTERN}))?")
_REFERENCE_HANDLE = re.compile(rf"ref1:([1-9][0-9]{{0,9}})/({SLUG_PATTERN})")


def _status_for(err: SecretServerError) -> grpc.StatusCode:
    # Secret Server reports many access failures as HTTP 400 with an
    # API_AccessDenied* error code (for example API_AccessDeniedOnFolder).
    if err.code.startswith("API_AccessDenied"):
        return grpc.StatusCode.PERMISSION_DENIED
    if err.status == 401:
        return grpc.StatusCode.UNAUTHENTICATED
    if err.status == 403:
        return grpc.StatusCode.PERMISSION_DENIED
    if err.status == 404:
        return grpc.StatusCode.NOT_FOUND
    if err.status == 0 or err.status >= 500:
        return grpc.StatusCode.UNAVAILABLE
    return grpc.StatusCode.FAILED_PRECONDITION


class CredentialDriverService(pb_grpc.CredentialDriverServicer):
    def __init__(self, config: DriverConfig, client: SecretServerClient):
        self._config = config
        self._client = client
        self._site_id: Optional[int] = config.site_id

    # -- protocol negotiation -------------------------------------------

    def GetCapabilities(self, request, context):
        if not request.HasField("gateway"):
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "gateway did not provide protocol metadata")
        gateway = request.gateway
        if not gateway.HasField("protocol_version") or gateway.protocol_version.major != PROTOCOL_MAJOR:
            major = gateway.protocol_version.major if gateway.HasField("protocol_version") else "none"
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                f"unsupported gateway credential protocol major version {major}; driver supports {PROTOCOL_MAJOR}",
            )
        if CONTRACT_CAPABILITY not in gateway.supported_capabilities:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"gateway does not advertise {CONTRACT_CAPABILITY}")
        unsupported = [cap for cap in gateway.required_capabilities if cap != CONTRACT_CAPABILITY]
        if unsupported:
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "driver does not support gateway-required capabilities: " + ", ".join(sorted(unsupported)),
            )
        return pb.GetCredentialDriverCapabilitiesResponse(
            driver_name=DRIVER_NAME,
            driver_version=__version__,
            backend_kind="delinea-secret-server",
            supports_list=False,
            supports_expires_at=False,
            extension=extension_pb2.PeerMetadata(
                protocol_version=extension_pb2.ProtocolVersion(major=PROTOCOL_MAJOR, minor=PROTOCOL_MINOR),
                implementation_name=IMPLEMENTATION_NAME,
                implementation_version=__version__,
                supported_capabilities=[CONTRACT_CAPABILITY],
                required_capabilities=[CONTRACT_CAPABILITY],
            ),
        )

    # -- credential operations ------------------------------------------

    def StoreCredential(self, request, context):
        self._require(context, request.provider_id, "provider_id")
        self._require(context, request.credential_key, "credential_key")
        existing = request.existing_handle if request.HasField("existing_handle") else None
        if existing is not None and not existing.handle:
            existing = None
        raw_object_id = existing.metadata.get(OBJECT_ID_METADATA_KEY, "") if existing else request.object_id
        object_id = self._object_id(context, raw_object_id, request.provider_id)

        reference = self._parse_reference(context, request.value)
        if reference is not None:
            return self._attach(context, request, existing, object_id, *reference)
        if existing is not None and existing.handle.startswith(REFERENCE_HANDLE_PREFIX):
            # The driver never writes into a secret it doesn't own.
            secret_id, _ = self._reference_handle(context, existing.handle)
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                f"provider credential '{request.credential_key}' is attached to Secret Server secret {secret_id}, "
                "which OpenShell doesn't own; change the value in Secret Server, or attach another secret "
                "with secretserver:<id>",
            )

        name = managed_secret_name(
            request.workspace, request.provider_id, request.provider, request.credential_key, object_id
        )
        slug = self._config.field_slug
        comment = self._comment("update", request)
        try:
            if existing is not None:
                secret_id = self._secret_id(context, existing.handle)
                self._verify_owned(context, self._client.get_secret(secret_id, comment), name, request.credential_key)
                self._client.update_field(secret_id, slug, request.value, comment)
                action = "updated"
            else:
                matches = self._client.find_active_by_name(self._config.folder_id, name)
                if matches:
                    # A retried write after a partial failure reuses the managed secret.
                    secret_id = matches[0]
                    self._client.update_field(secret_id, slug, request.value, comment)
                    action = "updated"
                else:
                    secret_id = self._create_secret(context, name, request)
                    action = "created"
        except SecretServerError as err:
            context.abort(_status_for(err), f"Secret Server store failed: {err}")
        log.info(
            "%s secret %s for provider=%s key=%s workspace=%s",
            action,
            secret_id,
            request.provider,
            request.credential_key,
            request.workspace or "-",
        )
        return pb.StoreCredentialResponse(
            handle=datamodel_pb2.CredentialHandle(
                driver=DRIVER_NAME,
                handle=f"{HANDLE_PREFIX}{secret_id}",
                metadata={OBJECT_ID_METADATA_KEY: object_id},
            )
        )

    def ResolveCredentials(self, request, context):
        resolved = []
        for item in request.credentials:
            self._require(context, item.request_id, "request_id")
            if not item.HasField("handle") or not item.handle.handle:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"credential request '{item.request_id}' is missing handle")
            try:
                if item.handle.handle.startswith(REFERENCE_HANDLE_PREFIX):
                    value = self._resolve_attached(context, item)
                else:
                    value = self._resolve_stored(context, item)
            except SecretServerError as err:
                context.abort(_status_for(err), f"Secret Server resolve failed for '{item.request_id}': {err}")
            resolved.append(pb.ResolvedCredential(request_id=item.request_id, value=value))
        log.info("resolved %d provider credential(s)", len(resolved))
        return pb.ResolveCredentialsResponse(credentials=resolved)

    def DeleteCredential(self, request, context):
        if not request.HasField("handle") or not request.handle.handle:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "delete request is missing handle")
        if request.handle.handle.startswith(REFERENCE_HANDLE_PREFIX):
            # An attached secret belongs to its owner in Secret Server; detaching never touches it.
            secret_id, _ = self._reference_handle(context, request.handle.handle)
            log.info(
                "detached secret %s from provider=%s key=%s; the secret is unchanged",
                secret_id,
                request.provider,
                request.credential_key,
            )
            return pb.DeleteCredentialResponse()
        object_id = self._object_id(context, request.handle.metadata.get(OBJECT_ID_METADATA_KEY, ""), request.provider_id)
        name = managed_secret_name(
            request.workspace, request.provider_id, request.provider, request.credential_key, object_id
        )
        secret_id = self._secret_id(context, request.handle.handle)
        try:
            secret = self._client.get_secret(secret_id, self._comment("delete", request))
        except SecretServerError as err:
            if err.status == 404:
                log.info("secret %s already absent; delete is a no-op", secret_id)
                return pb.DeleteCredentialResponse()
            context.abort(_status_for(err), f"Secret Server delete failed: {err}")
        if not self._verify_owned(context, secret, name, request.credential_key, allow_inactive=True):
            log.info("secret %s already deactivated; delete is a no-op", secret_id)
            return pb.DeleteCredentialResponse()
        try:
            self._client.deactivate_secret(secret_id)
        except SecretServerError as err:
            context.abort(_status_for(err), f"Secret Server delete failed: {err}")
        log.info("deactivated secret %s for provider=%s key=%s", secret_id, request.provider, request.credential_key)
        return pb.DeleteCredentialResponse()

    def ListCredentials(self, request, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "the Secret Server credential driver does not support listing")

    # -- attached secrets -----------------------------------------------

    def _attach(self, context, request, existing, object_id: str, secret_id: int, slug: str):
        if not self._config.reference_folder_ids:
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "Secret Server references are disabled; list the folders OpenShell may use in reference_folder_ids",
            )
        try:
            secret = self._client.get_secret(secret_id, self._comment("attach", request))
            self._check_attachable(context, secret, secret_id, slug)
            if existing is not None and existing.handle.startswith(HANDLE_PREFIX):
                # The credential used to hold a value the driver stored; retire that copy.
                self._retire_stored(context, request, existing, object_id)
        except SecretServerError as err:
            context.abort(_status_for(err), f"Secret Server attach failed for '{request.credential_key}': {err}")
        log.info(
            "attached secret %s (field %s) to provider=%s key=%s workspace=%s",
            secret_id,
            slug,
            request.provider,
            request.credential_key,
            request.workspace or "-",
        )
        binding = reference_binding(
            request.workspace, request.provider_id, request.provider, request.credential_key, object_id, secret_id, slug
        )
        return pb.StoreCredentialResponse(
            handle=datamodel_pb2.CredentialHandle(
                driver=DRIVER_NAME,
                handle=f"{REFERENCE_HANDLE_PREFIX}{secret_id}/{slug}",
                metadata={OBJECT_ID_METADATA_KEY: object_id, BINDING_METADATA_KEY: binding},
            )
        )

    def _resolve_attached(self, context, item) -> str:
        secret_id, slug = self._reference_handle(context, item.handle.handle)
        object_id = self._object_id(context, item.handle.metadata.get(OBJECT_ID_METADATA_KEY, ""), item.provider_id)
        expected = reference_binding(
            item.workspace, item.provider_id, item.provider, item.credential_key, object_id, secret_id, slug
        )
        if item.handle.metadata.get(BINDING_METADATA_KEY, "") != expected:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"handle does not belong to provider credential '{item.credential_key}'",
            )
        comment = self._comment("resolve", item)
        secret = self._client.get_secret(secret_id, comment)
        # Re-checked on every read: deactivating the secret, or moving it out of
        # an allowed folder, cuts OpenShell off at the next resolve.
        self._check_attachable(context, secret, secret_id, slug)
        value = self._extract_value(secret, secret_id, slug, comment)
        if not value:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"field '{slug}' of Secret Server secret {secret_id} is empty")
        return value

    def _check_attachable(self, context, secret: Dict[str, Any], secret_id: int, slug: str) -> None:
        folder_id = int(secret.get("folderId", -1))
        if folder_id == self._config.folder_id or folder_id not in self._config.reference_folder_ids:
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"Secret Server secret {secret_id} is not in a folder OpenShell may use (reference_folder_ids)",
            )
        if secret.get("active", True) is False:
            context.abort(grpc.StatusCode.NOT_FOUND, f"Secret Server secret {secret_id} has been deactivated")
        self._check_checkout_policy(context, secret, secret_id)
        if not any(item.get("slug") == slug for item in secret.get("items") or []):
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"Secret Server secret {secret_id} has no field '{slug}'")

    def _retire_stored(self, context, request, existing, object_id: str) -> None:
        name = managed_secret_name(
            request.workspace, request.provider_id, request.provider, request.credential_key, object_id
        )
        old_id = self._secret_id(context, existing.handle)
        try:
            secret = self._client.get_secret(old_id, self._comment("retire", request))
        except SecretServerError as err:
            if err.status == 404:
                return
            raise
        if self._verify_owned(context, secret, name, request.credential_key, allow_inactive=True):
            self._client.deactivate_secret(old_id)
            log.info("deactivated secret %s; provider=%s key=%s now uses an attached secret",
                     old_id, request.provider, request.credential_key)

    # -- stored secrets -----------------------------------------------------

    def _resolve_stored(self, context, item) -> str:
        object_id = self._object_id(context, item.handle.metadata.get(OBJECT_ID_METADATA_KEY, ""), item.provider_id)
        name = managed_secret_name(item.workspace, item.provider_id, item.provider, item.credential_key, object_id)
        secret_id = self._secret_id(context, item.handle.handle)
        comment = self._comment("resolve", item)
        secret = self._client.get_secret(secret_id, comment)
        self._verify_owned(context, secret, name, item.credential_key)
        self._check_checkout_policy(context, secret, secret_id)
        return self._extract_value(secret, secret_id, self._config.field_slug, comment)

    def _create_secret(self, context, name: str, request) -> int:
        # The stub is used only to learn the template's field IDs. The create body
        # is the minimal shape Secret Server accepts (name, template, folder, and
        # {fieldId, itemValue} items); posting the full stub back is rejected.
        stub = self._client.get_stub(self._config.template_id, self._config.folder_id)
        fields = {item.get("slug"): item for item in stub.get("items") or [] if item.get("slug")}
        slug = self._config.field_slug
        if slug not in fields or fields[slug].get("fieldId") is None:
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                f"Secret Server template {self._config.template_id} has no field with slug '{slug}'",
            )
        values = {slug: request.value}
        if "notes" in fields:
            values["notes"] = (
                f"Managed by NVIDIA OpenShell. workspace={request.workspace or '-'} "
                f"provider={request.provider} provider_id={request.provider_id} key={request.credential_key}"
            )
        if "username" in fields:
            values["username"] = request.credential_key
        for location_slug in ("resource", "url"):
            if location_slug in fields:
                values[location_slug] = f"openshell://{request.workspace or 'default'}/{request.provider}"
        payload: Dict[str, Any] = {
            "name": name,
            "secretTemplateId": self._config.template_id,
            "folderId": self._config.folder_id,
            "items": [
                {"fieldId": fields[field_slug]["fieldId"], "itemValue": value}
                for field_slug, value in values.items()
                if fields[field_slug].get("fieldId") is not None
            ],
        }
        payload["siteId"] = self._resolve_site_id(context, stub)
        created = self._client.create_secret(payload)
        return int(created["id"])

    def _resolve_site_id(self, context, stub: Dict[str, Any]) -> int:
        """Secret Server requires a site (>= 1) on create; stubs may carry 0."""
        if self._site_id:
            return self._site_id
        stub_site = stub.get("siteId")
        if stub_site and int(stub_site) > 0:
            self._site_id, source = int(stub_site), "secret stub"
        else:
            self._site_id, source = self._client.discover_site_id(), "discovered"
        if not self._site_id:
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "could not determine a Secret Server site for new secrets; set site_id (SS_SITE_ID)",
            )
        log.info("using Secret Server site %s (%s)", self._site_id, source)
        return self._site_id

    def _verify_owned(
        self,
        context,
        secret: Dict[str, Any],
        expected_name: str,
        credential_key: str,
        allow_inactive: bool = False,
    ) -> bool:
        """Abort unless the secret is the managed one; return whether it is active."""
        owned = (
            secret.get("name") == expected_name
            and int(secret.get("folderId", -1)) == self._config.folder_id
        )
        if not owned:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"handle does not match the managed Secret Server secret for provider credential '{credential_key}'",
            )
        active = secret.get("active", True) is not False
        if not active and not allow_inactive:
            context.abort(
                grpc.StatusCode.NOT_FOUND,
                f"the Secret Server secret for provider credential '{credential_key}' has been deactivated",
            )
        return active

    # -- helpers ----------------------------------------------------------

    def _extract_value(self, secret: Dict[str, Any], secret_id: int, slug: str, comment: Optional[str]) -> str:
        for item in secret.get("items") or []:
            if item.get("slug") == slug:
                value: Optional[str] = item.get("itemValue")
                if value:
                    return value
                break
        # Some deployments omit protected values from the secret model.
        return self._client.get_field(secret_id, slug, comment)

    def _comment(self, operation: str, request) -> Optional[str]:
        """The audit comment Secret Server records with a read. Never includes a value."""
        if not self._config.audit_comments:
            return None
        text = (
            f"OpenShell {operation}: provider={request.provider} key={request.credential_key} "
            f"workspace={request.workspace or '-'}"
        )
        return "".join(ch for ch in text if ch.isprintable())[:250]

    @staticmethod
    def _check_checkout_policy(context, secret: Dict[str, Any], secret_id: int) -> None:
        # OpenShell keeps a resolved value for the sandbox's lifetime, so a secret
        # that changes its password on check-in would stop working right away.
        if secret.get("checkOutEnabled") and secret.get("checkOutChangePasswordEnabled"):
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                f"Secret Server secret {secret_id} changes its password on check-in, so the value OpenShell "
                "holds would stop working; turn that off or use another secret",
            )

    def _parse_reference(self, context, value: str) -> Optional[Tuple[int, str]]:
        text = value.strip()
        if not text.startswith(REFERENCE_PREFIX):
            return None
        match = _REFERENCE.fullmatch(text)
        if not match:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "a Secret Server reference looks like secretserver:<secret id> or secretserver:<secret id>/<field slug>",
            )
        return int(match.group(1)), match.group(2) or self._config.field_slug

    @staticmethod
    def _reference_handle(context, handle: str) -> Tuple[int, str]:
        match = _REFERENCE_HANDLE.fullmatch(handle)
        if not match:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Secret Server credential handle is malformed")
        return int(match.group(1)), match.group(2)

    @staticmethod
    def _secret_id(context, handle: str) -> int:
        if not handle.startswith(HANDLE_PREFIX):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Secret Server credential handle is malformed")
        raw = handle[len(HANDLE_PREFIX):]
        if not raw.isdigit() or int(raw) <= 0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Secret Server credential handle is malformed")
        return int(raw)

    @staticmethod
    def _object_id(context, raw: str, provider_id: str) -> str:
        try:
            return requested_object_id(raw, provider_id)
        except ValueError as err:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(err))

    @staticmethod
    def _require(context, value: str, field_name: str) -> None:
        if not value:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"{field_name} is required")
