"""OpenShell CredentialDriver gRPC service backed by Delinea Secret Server.

Each gateway-managed provider credential becomes one Secret Server secret in a
dedicated folder. The handle returned to the gateway is `v1:<secret id>`, and
every read, update and delete re-checks that the secret behind the handle still
carries the managed name derived from the identity the gateway presents.
"""

import logging
from typing import Any, Dict, Optional

import grpc

import credential_driver_pb2 as pb
import credential_driver_pb2_grpc as pb_grpc
import datamodel_pb2
import extension_pb2

from . import __version__
from .config import DriverConfig
from .naming import managed_secret_name, requested_object_id
from .secret_server import SecretServerClient, SecretServerError

log = logging.getLogger("ss_driver.service")

DRIVER_NAME = "delinea-secret-server"
IMPLEMENTATION_NAME = "delinea/secret-server-credential-driver"
CONTRACT_CAPABILITY = "openshell.credentials.contract"
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
HANDLE_PREFIX = "v1:"
OBJECT_ID_METADATA_KEY = "object_id"


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
        name = managed_secret_name(
            request.workspace, request.provider_id, request.provider, request.credential_key, object_id
        )
        slug = self._config.field_slug
        try:
            if existing is not None:
                secret_id = self._secret_id(context, existing.handle)
                self._verify_owned(context, self._client.get_secret(secret_id), name, request.credential_key)
                self._client.update_field(secret_id, slug, request.value)
                action = "updated"
            else:
                matches = self._client.find_active_by_name(self._config.folder_id, name)
                if matches:
                    # A retried write after a partial failure reuses the managed secret.
                    secret_id = matches[0]
                    self._client.update_field(secret_id, slug, request.value)
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
            object_id = self._object_id(context, item.handle.metadata.get(OBJECT_ID_METADATA_KEY, ""), item.provider_id)
            name = managed_secret_name(item.workspace, item.provider_id, item.provider, item.credential_key, object_id)
            secret_id = self._secret_id(context, item.handle.handle)
            try:
                secret = self._client.get_secret(secret_id)
                self._verify_owned(context, secret, name, item.credential_key)
                value = self._extract_value(secret, secret_id)
            except SecretServerError as err:
                context.abort(_status_for(err), f"Secret Server resolve failed for '{item.request_id}': {err}")
            resolved.append(pb.ResolvedCredential(request_id=item.request_id, value=value))
        log.info("resolved %d provider credential(s)", len(resolved))
        return pb.ResolveCredentialsResponse(credentials=resolved)

    def DeleteCredential(self, request, context):
        if not request.HasField("handle") or not request.handle.handle:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "delete request is missing handle")
        object_id = self._object_id(context, request.handle.metadata.get(OBJECT_ID_METADATA_KEY, ""), request.provider_id)
        name = managed_secret_name(
            request.workspace, request.provider_id, request.provider, request.credential_key, object_id
        )
        secret_id = self._secret_id(context, request.handle.handle)
        try:
            secret = self._client.get_secret(secret_id)
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

    # -- helpers ----------------------------------------------------------

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

    def _extract_value(self, secret: Dict[str, Any], secret_id: int) -> str:
        for item in secret.get("items") or []:
            if item.get("slug") == self._config.field_slug:
                value: Optional[str] = item.get("itemValue")
                if value is not None:
                    return value
                break
        # Some deployments omit protected values from the secret model.
        return self._client.get_field(secret_id, self._config.field_slug)

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
