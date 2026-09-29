# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""End-to-end test: launch the driver the way the OpenShell gateway does and
exercise the CredentialDriver contract against a mock Secret Server.

Run: .venv/bin/python tests/e2e_test.py
"""

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.request import Request, urlopen

import grpc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # the mock lives next to this file

import mock_secret_server as mock  # noqa: E402
from ss_driver._proto import credential_driver_pb2 as pb  # noqa: E402
from ss_driver._proto import credential_driver_pb2_grpc as pb_grpc  # noqa: E402
from ss_driver._proto import datamodel_pb2, extension_pb2  # noqa: E402
from ss_driver.config import ConfigError, DriverConfig, load_config  # noqa: E402
from ss_driver.naming import reference_binding  # noqa: E402
from ss_driver.secret_server import SecretServerClient  # noqa: E402

CONTRACT = "openshell.credentials.contract"
CONFIGURED_DRIVER_NAME = "delinea-secret-server"
FOLDER_ID = 42
SECURITY_FOLDER_ID = 77  # a folder the security team owns; the driver may only read from it
SS_USER = "svc-openshell-driver"
SS_PASSWORD = "Pa55-for-the-driver-account"
PLATFORM_CLIENT_ID = "openshell-driver@tenant"
PLATFORM_CLIENT_SECRET = "platform-client-secret-for-tests"

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    mark = "PASS" if condition else "FAIL"
    print(f"{mark}  {name}" + (f"  [{detail}]" if detail else ""))


def expect_error(call, code):
    try:
        call()
    except grpc.RpcError as err:
        return err.code() == code, f"{err.code().name}: {err.details()}"
    return False, "call unexpectedly succeeded"


def gateway_metadata(major=1):
    return extension_pb2.PeerMetadata(
        protocol_version=extension_pb2.ProtocolVersion(major=major, minor=0),
        implementation_name="openshell/gateway",
        implementation_version="0.1.2",
        supported_capabilities=[CONTRACT],
        required_capabilities=[CONTRACT],
    )


def gateway_side_negotiation(extension):
    """Mirror of openshell_core::extension_protocol::negotiate for the credentials family."""
    gateway = gateway_metadata()
    if extension is None or not extension.HasField("protocol_version"):
        return False, "missing protocol metadata"
    if extension.protocol_version.major != gateway.protocol_version.major:
        return False, f"incompatible protocol {extension.protocol_version.major}"
    for field_name in ("implementation_name", "implementation_version"):
        value = getattr(extension, field_name)
        if not value or len(value.encode()) > 128 or value.strip() != value:
            return False, f"invalid {field_name}"
    missing_ext = [c for c in gateway.required_capabilities if c not in extension.supported_capabilities]
    missing_gw = [c for c in extension.required_capabilities if c not in gateway.supported_capabilities]
    if missing_ext or missing_gw:
        return False, f"missing capabilities ext={missing_ext} gateway={missing_gw}"
    return True, f"{extension.implementation_name} {extension.implementation_version} protocol {extension.protocol_version.major}.{extension.protocol_version.minor}"


def as_gateway_handle(handle):
    """The gateway stamps its configured driver name onto stored handles."""
    stamped = datamodel_pb2.CredentialHandle()
    stamped.CopyFrom(handle)
    stamped.driver = CONFIGURED_DRIVER_NAME
    return stamped


def mock_post(base_url, path, payload):
    request = Request(f"{base_url}{path}", data=json.dumps(payload).encode(), method="POST",
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read() or b"null")


def mock_get(base_url, path):
    with urlopen(f"{base_url}{path}", timeout=5) as response:
        return json.loads(response.read() or b"null")


def password_of(state, secret_id):
    return next(i["itemValue"] for i in state.secrets[secret_id]["items"] if i["slug"] == "password")


def config_checks(workdir):
    print("-- configuration --")
    path = os.path.join(workdir, "config-check.json")
    base = {"base_url": "https://vault.example.com", "folder_id": FOLDER_ID, "template_id": mock.TEMPLATE_ID,
            "username": "u", "password": "p"}

    def load(extra, env=None):
        with open(path, "w") as handle:
            json.dump(dict(base, **extra), handle)
        saved = {name: os.environ.get(name) for name in env or {}}
        os.environ.update(env or {})
        try:
            return load_config(path)
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    config = load({})
    check("references are off and audit comments on by default",
          config.reference_folder_ids == () and config.audit_comments)
    config = load({}, {"SS_REFERENCE_FOLDER_IDS": "77, 78", "SS_AUDIT_COMMENTS": "false"})
    check("SS_REFERENCE_FOLDER_IDS and SS_AUDIT_COMMENTS are read from the environment",
          config.reference_folder_ids == (77, 78) and not config.audit_comments)
    try:
        load({"reference_folder_ids": [FOLDER_ID]})
        check("the driver's own folder can't be a reference folder", False)
    except ConfigError as err:
        check("the driver's own folder can't be a reference folder", True, str(err))
    print()


def platform_phase(base_url, state, workdir):
    """Same driver, authenticating as a Delinea Platform service account."""
    print("\n-- Delinea Platform service-account login --")
    secret_file = os.path.join(workdir, "platform-client-secret")
    with open(os.open(secret_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as handle:
        handle.write(PLATFORM_CLIENT_SECRET)
    config_path = os.path.join(workdir, "driver-platform.json")
    with open(config_path, "w") as handle:
        json.dump({
            "base_url": base_url,
            "platform_hostname": base_url,
            "client_id": PLATFORM_CLIENT_ID,
            "client_secret_file": secret_file,
            "folder_id": FOLDER_ID,
            "template_id": mock.TEMPLATE_ID,
        }, handle)
    socket_path = os.path.join(workdir, "run", "platform.sock")
    log_path = os.path.join(workdir, "driver-platform.log")
    grants_before = list(state.grants)
    with open(log_path, "w") as log_file:
        driver = subprocess.Popen(
            [sys.executable, "-m", "ss_driver", "--config", config_path, "--bind-socket", socket_path],
            cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT), stdout=log_file, stderr=subprocess.STDOUT)
        stub = pb_grpc.CredentialDriverStub(grpc.insecure_channel(f"unix:{socket_path}"))
        try:
            deadline = time.time() + 20
            while time.time() < deadline and not os.path.exists(socket_path):
                time.sleep(0.2)
            identity = dict(provider="anthropic", credential_key="ANTHROPIC_API_KEY", workspace="default",
                            provider_id=str(uuid.uuid4()))
            handle = as_gateway_handle(stub.StoreCredential(
                pb.StoreCredentialRequest(value="sk-ant-poc-value", **identity), timeout=10).handle)

            def resolve():
                return stub.ResolveCredentials(pb.ResolveCredentialsRequest(credentials=[
                    pb.ResolveCredentialRequest(request_id="p1", handle=handle, **identity)]),
                    timeout=10).credentials[0].value

            check("platform login: store and resolve work", resolve() == "sk-ant-poc-value")
            mock_post(base_url, "/_test/expire-tokens", {})
            check("platform login: re-authenticates after token expiry", resolve() == "sk-ant-poc-value")
            new_grants = state.grants[len(grants_before):]
            check("platform login uses client credentials only",
                  new_grants and all(grant == "client_credentials" for grant in new_grants),
                  ", ".join(new_grants))
            ok, detail = expect_error(lambda: stub.StoreCredential(pb.StoreCredentialRequest(
                value="secretserver:1000", **dict(identity, credential_key="OTHER_KEY")), timeout=10),
                grpc.StatusCode.FAILED_PRECONDITION)
            check("references are refused when reference_folder_ids is empty", ok, detail)
            stub.DeleteCredential(pb.DeleteCredentialRequest(handle=handle, **identity), timeout=10)
        finally:
            driver.send_signal(signal.SIGTERM)
            try:
                driver.wait(timeout=10)
            except subprocess.TimeoutExpired:
                driver.kill()
    with open(log_path) as handle:
        log_text = handle.read()
    check("platform driver log contains no client secret or values",
          PLATFORM_CLIENT_SECRET not in log_text and "sk-ant-poc-value" not in log_text)


def main():
    server, state, base_url = mock.start({SS_USER: SS_PASSWORD}, {PLATFORM_CLIENT_ID: PLATFORM_CLIENT_SECRET})
    workdir = tempfile.mkdtemp(prefix="ssd-")
    config_checks(workdir)
    socket_path = os.path.join(workdir, "run", "secret-server.sock")
    password_file = os.path.join(workdir, "ss-password")
    with open(os.open(password_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as handle:
        handle.write(SS_PASSWORD)
    config_path = os.path.join(workdir, "driver.json")
    with open(config_path, "w") as handle:
        json.dump({
            "base_url": base_url,
            "folder_id": FOLDER_ID,
            "template_id": mock.TEMPLATE_ID,
            "field_slug": "password",
            "username": SS_USER,
            "password_file": password_file,
            "reference_folder_ids": [SECURITY_FOLDER_ID],
        }, handle)
    log_path = os.path.join(workdir, "driver.log")

    print(f"mock Secret Server: {base_url}  socket: {socket_path}\n")
    log_file = open(log_path, "w")
    # Same launch shape the gateway uses for `command`: args + --bind-socket <socket_path>.
    driver = subprocess.Popen(
        [sys.executable, "-m", "ss_driver", "--config", config_path, "--bind-socket", socket_path],
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=ROOT),
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    channel = grpc.insecure_channel(f"unix:{socket_path}")
    stub = pb_grpc.CredentialDriverStub(channel)

    try:
        # 1. readiness + negotiation, as in connect_ready_credential_driver
        capabilities = None
        deadline = time.time() + 20
        while time.time() < deadline and driver.poll() is None:
            if os.path.exists(socket_path):
                try:
                    capabilities = stub.GetCapabilities(
                        pb.GetCredentialDriverCapabilitiesRequest(gateway=gateway_metadata()), timeout=5)
                    break
                except grpc.RpcError:
                    pass
            time.sleep(0.2)
        check("driver starts and answers GetCapabilities over the Unix socket", capabilities is not None)
        if capabilities is None:
            return 1
        ok, detail = gateway_side_negotiation(capabilities.extension)
        check("gateway-side protocol negotiation succeeds", ok, detail)
        check("capabilities report backend kind and no listing",
              capabilities.backend_kind == "delinea-secret-server" and not capabilities.supports_list)
        mode = stat.S_IMODE(os.stat(socket_path).st_mode)
        check("socket is owner-only (0600)", mode == 0o600, oct(mode))
        ok, detail = expect_error(lambda: stub.GetCapabilities(
            pb.GetCredentialDriverCapabilitiesRequest(gateway=gateway_metadata(major=2)), timeout=5),
            grpc.StatusCode.FAILED_PRECONDITION)
        check("driver rejects an incompatible gateway protocol", ok, detail)

        # 2. store
        github = dict(provider="github-work", credential_key="GITHUB_TOKEN", workspace="default",
                      provider_id=str(uuid.uuid4()))
        openai = dict(provider="openai-prod", credential_key="OPENAI_API_KEY", workspace="default",
                      provider_id=str(uuid.uuid4()))
        gh_handle = as_gateway_handle(stub.StoreCredential(
            pb.StoreCredentialRequest(value="ghp_poc_value_1", **github), timeout=10).handle)
        oa_handle = as_gateway_handle(stub.StoreCredential(
            pb.StoreCredentialRequest(value="sk-poc-openai-value", **openai), timeout=10).handle)
        gh_id = int(gh_handle.handle.split(":", 1)[1])
        check("store returns an opaque v1 handle bound to the provider",
              gh_handle.handle.startswith("v1:") and gh_handle.metadata["object_id"] == github["provider_id"],
              gh_handle.handle)
        stored = state.secrets[gh_id]
        notes = next(i["itemValue"] for i in stored["items"] if i["slug"] == "notes")
        check("secret is created in the managed folder with a hashed name",
              stored["folderId"] == FOLDER_ID and stored["name"].startswith("openshell-"), stored["name"])
        check("secret notes carry provider context but not the value",
              "github-work" in notes and "GITHUB_TOKEN" in notes and "ghp_poc_value_1" not in notes)

        def resolve(handle, identity, request_id="req"):
            response = stub.ResolveCredentials(pb.ResolveCredentialsRequest(credentials=[
                pb.ResolveCredentialRequest(request_id=request_id, handle=handle, **identity)]), timeout=10)
            return response.credentials[0].value

        # 3. batch resolve
        response = stub.ResolveCredentials(pb.ResolveCredentialsRequest(credentials=[
            pb.ResolveCredentialRequest(request_id="req-1", handle=gh_handle, **github),
            pb.ResolveCredentialRequest(request_id="req-2", handle=oa_handle, **openai),
        ]), timeout=10)
        values = {c.request_id: c.value for c in response.credentials}
        check("batch resolve returns each value keyed by request_id",
              values == {"req-1": "ghp_poc_value_1", "req-2": "sk-poc-openai-value"})

        # 4. overwrite through existing_handle, then an idempotent retry
        updated = stub.StoreCredential(pb.StoreCredentialRequest(
            value="ghp_poc_value_2", existing_handle=gh_handle, **github), timeout=10).handle
        check("update through existing_handle keeps the same secret",
              updated.handle == gh_handle.handle and resolve(gh_handle, github) == "ghp_poc_value_2")
        retried = stub.StoreCredential(pb.StoreCredentialRequest(value="ghp_poc_value_3", **github), timeout=10).handle
        same_name = [s for s in state.secrets.values() if s["name"] == stored["name"] and s["active"]]
        check("a retried store without a handle reuses the managed secret",
              retried.handle == gh_handle.handle and len(same_name) == 1)

        # 5. refresh-style staged write with a new object_id
        staged = as_gateway_handle(stub.StoreCredential(pb.StoreCredentialRequest(
            value="ghp_staged_refresh", object_id="refresh-0002", **github), timeout=10).handle)
        check("a staged refresh write gets its own secret",
              staged.handle != gh_handle.handle and staged.metadata["object_id"] == "refresh-0002"
              and resolve(staged, github) == "ghp_staged_refresh" and resolve(gh_handle, github) == "ghp_poc_value_3")

        # 6. Secret Server stays the source of truth
        mock_post(base_url, f"/_test/rotate/{gh_id}", {"value": "ghp_rotated_by_secret_server"})
        check("a rotation inside Secret Server is returned on the next resolve",
              resolve(gh_handle, github) == "ghp_rotated_by_secret_server")

        # 7. handle binding
        ok, detail = expect_error(lambda: resolve(gh_handle, dict(github, provider_id=openai["provider_id"])),
                                  grpc.StatusCode.INVALID_ARGUMENT)
        check("a handle replayed under another provider is refused", ok, detail)
        ok, detail = expect_error(lambda: resolve(gh_handle, dict(github, credential_key="GH_TOKEN")),
                                  grpc.StatusCode.INVALID_ARGUMENT)
        check("a handle replayed under another credential key is refused", ok, detail)
        foreign_id = state.add_secret(name=stored["name"], folder_id=99, value="prod-db-root-password")
        forged = datamodel_pb2.CredentialHandle(driver=CONFIGURED_DRIVER_NAME, handle=f"v1:{foreign_id}",
                                                metadata={"object_id": github["provider_id"]})
        ok, detail = expect_error(lambda: resolve(forged, github), grpc.StatusCode.INVALID_ARGUMENT)
        check("a forged handle to a secret outside the managed folder is refused", ok, detail)
        malformed = datamodel_pb2.CredentialHandle(driver=CONFIGURED_DRIVER_NAME, handle="v1:../../etc")
        ok, detail = expect_error(lambda: resolve(malformed, github), grpc.StatusCode.INVALID_ARGUMENT)
        check("a malformed handle is refused", ok, detail)

        # 8. session expiry
        mock_post(base_url, "/_test/expire-tokens", {})
        check("the driver re-authenticates when its Secret Server session expires",
              resolve(gh_handle, github) == "ghp_rotated_by_secret_server")

        # 9. list and delete
        ok, detail = expect_error(lambda: stub.ListCredentials(pb.ListCredentialsRequest(), timeout=5),
                                  grpc.StatusCode.UNIMPLEMENTED)
        check("ListCredentials reports UNIMPLEMENTED", ok, detail)
        staged_id = int(staged.handle.split(":", 1)[1])
        stub.DeleteCredential(pb.DeleteCredentialRequest(handle=staged, **github), timeout=10)
        check("delete deactivates the secret in Secret Server", state.secrets[staged_id]["active"] is False)
        ok, detail = expect_error(lambda: resolve(staged, github), grpc.StatusCode.NOT_FOUND)
        check("a deleted credential no longer resolves", ok, detail)
        try:
            stub.DeleteCredential(pb.DeleteCredentialRequest(handle=staged, **github), timeout=10)
            check("deleting twice is a no-op", True)
        except grpc.RpcError as err:
            check("deleting twice is a no-op", False, err.details())

        # 9b. servers that keep returning deactivated secrets with active=false
        mock_post(base_url, "/_test/inactive-readable", {"enabled": True})
        extra = dict(provider="slack-bot", credential_key="SLACK_BOT_TOKEN", workspace="default",
                     provider_id=str(uuid.uuid4()))
        extra_handle = as_gateway_handle(stub.StoreCredential(
            pb.StoreCredentialRequest(value="xoxb-poc-value", **extra), timeout=10).handle)
        stub.DeleteCredential(pb.DeleteCredentialRequest(handle=extra_handle, **extra), timeout=10)
        ok, detail = expect_error(lambda: resolve(extra_handle, extra), grpc.StatusCode.NOT_FOUND)
        check("a deactivated secret still returned by the server doesn't resolve", ok, detail)
        try:
            stub.DeleteCredential(pb.DeleteCredentialRequest(handle=extra_handle, **extra), timeout=10)
            check("deleting a deactivated-but-readable secret again is a no-op", True)
        except grpc.RpcError as err:
            check("deleting a deactivated-but-readable secret again is a no-op", False, err.details())
        mock_post(base_url, "/_test/inactive-readable", {"enabled": False})

        # 10. a secret the security team owns, attached by reference
        security_value = "acme_live_security_owned"
        sec_id = state.add_secret("Acme Orders API (production)", SECURITY_FOLDER_ID, security_value,
                                  extra={"username": "orders-svc"})
        orders = dict(provider="acme-orders", credential_key="ORDERS_API_KEY", workspace="default",
                      provider_id=str(uuid.uuid4()))
        secrets_before = len(state.secrets)
        ref = as_gateway_handle(stub.StoreCredential(
            pb.StoreCredentialRequest(value=f"secretserver:{sec_id}", **orders), timeout=10).handle)
        copies = [s["id"] for s in state.secrets.values()
                  if s["id"] != sec_id and any(i.get("itemValue") == security_value for i in s["items"])]
        check("attaching an existing secret returns a pointer and copies nothing",
              ref.handle == f"ref1:{sec_id}/password" and len(state.secrets) == secrets_before and not copies,
              ref.handle)
        check("the attached secret resolves to the security team's value", resolve(ref, orders) == security_value)
        mock_post(base_url, f"/_test/rotate/{sec_id}", {"value": "acme_live_rotated_by_security"})
        check("a rotation by the secret's owner reaches the next resolve",
              resolve(ref, orders) == "acme_live_rotated_by_security")
        orders_user = dict(orders, credential_key="ORDERS_API_USER")
        user_ref = as_gateway_handle(stub.StoreCredential(
            pb.StoreCredentialRequest(value=f"secretserver:{sec_id}/username", **orders_user), timeout=10).handle)
        check("a reference can name the field to use", resolve(user_ref, orders_user) == "orders-svc", user_ref.handle)

        outside_id = state.add_secret("payroll-db", 99, "payroll-db-root-password")
        ok, detail = expect_error(lambda: stub.StoreCredential(
            pb.StoreCredentialRequest(value=f"secretserver:{outside_id}", **orders), timeout=10),
            grpc.StatusCode.PERMISSION_DENIED)
        check("a secret outside reference_folder_ids can't be attached", ok, detail)
        ok, detail = expect_error(lambda: stub.StoreCredential(
            pb.StoreCredentialRequest(value=f"secretserver:{gh_id}", **orders), timeout=10),
            grpc.StatusCode.PERMISSION_DENIED)
        check("another provider's stored secret can't be attached by ID", ok, detail)
        ok, detail = expect_error(lambda: stub.StoreCredential(
            pb.StoreCredentialRequest(value="secretserver:12ab", **orders), timeout=10),
            grpc.StatusCode.INVALID_ARGUMENT)
        check("a malformed reference is refused", ok, detail)

        ok, detail = expect_error(lambda: resolve(ref, dict(orders, provider_id=github["provider_id"])),
                                  grpc.StatusCode.INVALID_ARGUMENT)
        check("a reference handle replayed under another provider is refused", ok, detail)
        forged_binding = reference_binding(orders["workspace"], orders["provider_id"], orders["provider"],
                                           orders["credential_key"], orders["provider_id"], outside_id, "password")
        forged_ref = datamodel_pb2.CredentialHandle(
            driver=CONFIGURED_DRIVER_NAME, handle=f"ref1:{outside_id}/password",
            metadata={"object_id": orders["provider_id"], "binding": forged_binding})
        ok, detail = expect_error(lambda: resolve(forged_ref, orders), grpc.StatusCode.PERMISSION_DENIED)
        check("a forged reference to a secret outside the allowed folders is refused", ok, detail)

        ok, detail = expect_error(lambda: stub.StoreCredential(pb.StoreCredentialRequest(
            value="acme_live_pasted_by_hand", existing_handle=ref, **orders), timeout=10),
            grpc.StatusCode.FAILED_PRECONDITION)
        check("a raw value can't overwrite an attached secret",
              ok and password_of(state, sec_id) == "acme_live_rotated_by_security", detail)
        oa_id = int(oa_handle.handle.split(":", 1)[1])
        switched = as_gateway_handle(stub.StoreCredential(pb.StoreCredentialRequest(
            value=f"secretserver:{sec_id}", existing_handle=oa_handle, **openai), timeout=10).handle)
        check("switching a stored value to a reference retires the driver's copy",
              switched.handle.startswith("ref1:") and state.secrets[oa_id]["active"] is False
              and resolve(switched, openai) == "acme_live_rotated_by_security")
        stub.DeleteCredential(pb.DeleteCredentialRequest(handle=ref, **orders), timeout=10)
        check("deleting the provider detaches the secret and never deactivates it",
              state.secrets[sec_id]["active"] is True
              and not any(e["action"] == "DEACTIVATE" and e["secretId"] == sec_id for e in state.audit))

        mock_post(base_url, f"/_test/secret-flags/{sec_id}", {"folderId": 99})
        ok, detail = expect_error(lambda: resolve(switched, openai), grpc.StatusCode.PERMISSION_DENIED)
        check("moving the secret out of an allowed folder cuts OpenShell off", ok, detail)
        mock_post(base_url, f"/_test/secret-flags/{sec_id}", {"folderId": SECURITY_FOLDER_ID, "active": False})
        ok, detail = expect_error(lambda: resolve(switched, openai), grpc.StatusCode.NOT_FOUND)
        check("deactivating the secret in Secret Server cuts OpenShell off", ok, detail)
        mock_post(base_url, f"/_test/secret-flags/{sec_id}", {"active": True, "requiresComment": True})
        check("a secret that requires a comment is readable, because every read carries one",
              resolve(switched, openai) == "acme_live_rotated_by_security")
        mock_post(base_url, f"/_test/secret-flags/{sec_id}", {"requiresComment": False, "checkOutEnabled": True})
        check("a secret that requires checkout is checked out and back in around the read",
              resolve(switched, openai) == "acme_live_rotated_by_security"
              and {"CHECKOUT", "CHECKIN"} <= {e["action"] for e in state.audit if e["secretId"] == sec_id})
        mock_post(base_url, f"/_test/secret-flags/{sec_id}", {"checkOutChangePasswordEnabled": True})
        ok, detail = expect_error(lambda: resolve(switched, openai), grpc.StatusCode.FAILED_PRECONDITION)
        check("a secret that changes its password on check-in is refused", ok, detail)
        mock_post(base_url, f"/_test/secret-flags/{sec_id}",
                  {"checkOutEnabled": False, "checkOutChangePasswordEnabled": False})

        # 11. audit trail in Secret Server
        audit = mock_get(base_url, "/_test/audit")
        driver_actions = {entry["action"] for entry in audit if entry["user"] == SS_USER}
        check("Secret Server audit records the driver's creates, reads, edits and deactivations",
              {"CREATE", "VIEW", "EDIT", "DEACTIVATE"} <= driver_actions, ", ".join(sorted(driver_actions)))
        views = [e for e in audit if e["user"] == SS_USER and e["action"] == "VIEW"]
        expected_note = "OpenShell resolve: provider=acme-orders key=ORDERS_API_KEY workspace=default"
        check("every read carries an audit comment naming the provider, key and workspace",
              views and all(e["notes"].startswith("OpenShell ") for e in views)
              and any(e["notes"] == expected_note for e in views), expected_note)
        reader = SecretServerClient(DriverConfig(base_url=base_url, folder_id=FOLDER_ID, template_id=mock.TEMPLATE_ID,
                                                 username=SS_USER, password=SS_PASSWORD))
        records = reader.secret_audits(sec_id)
        check("the secret's audit shows each OpenShell read with its context",
              any(r["action"] == "VIEW" and r["notes"] == expected_note for r in records),
              f"{len(records)} audit records for secret {sec_id}")
        print(f"      audit: {len(audit)} events, {len(views)} secret views by {SS_USER}")
    finally:
        driver.send_signal(signal.SIGTERM)
        try:
            driver.wait(timeout=10)
        except subprocess.TimeoutExpired:
            driver.kill()
        log_file.close()

    check("driver shuts down cleanly on SIGTERM and removes its socket",
          driver.returncode == 0 and not os.path.exists(socket_path), f"exit {driver.returncode}")
    with open(log_path) as handle:
        log_text = handle.read()
    leaked = [value for value in (
        "ghp_poc_value_1", "ghp_poc_value_2", "ghp_poc_value_3", "ghp_staged_refresh",
        "ghp_rotated_by_secret_server", "sk-poc-openai-value", "prod-db-root-password", "xoxb-poc-value", SS_PASSWORD,
        "acme_live_security_owned", "acme_live_rotated_by_security", "payroll-db-root-password",
        "acme_live_pasted_by_hand",
    ) + tuple(state.tokens.keys()) if value in log_text]
    check("driver log contains no secret values, passwords or tokens", not leaked,
          f"{len(log_text.splitlines())} log lines checked")

    platform_phase(base_url, state, workdir)
    server.shutdown()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed. Driver log: {log_path}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
