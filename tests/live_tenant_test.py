"""Live test of the credential driver against a Delinea Platform tenant.

Platform only. Run through live-test.sh, which runs the mock suite first and then
loads only the Platform env file you pass it, so standalone Secret Server
credentials (DELINEA_*) can't mix with the Platform ones:

    ./live-test.sh --env-file /path/to/platform.env

Environment: PLATFORM_HOSTNAME, PLATFORM_SERVICE_ACCOUNT, PLATFORM_SERVICE_PASSWORD. The driver signs in with Platform client credentials
(/identity/api/oauth2/token/xpmplatform, scope xpmheadless).

The Secret Server vault behind the Platform tenant comes from --vault-url or
OPENSHELL_PLATFORM_VAULT_URL; otherwise the test tries the Platform vault-broker
listing (/vaultbroker/api/vaults) and stops with instructions if that fails.

Safety contract: the test mutates only
resources it creates. It creates a folder named openshell-itest-<timestamp>,
stores random test values in it through the driver, and in a finally block
deactivates those secrets and deletes the folder. A sweep at the start of each
run removes anything left under the openshell-itest- prefix. If the account
can't create a folder, only read-only checks run and the write path is reported
as not verified.
"""

import argparse
import os
import secrets as pysecrets
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlparse

import grpc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (ROOT, os.path.join(ROOT, "generated")):
    if path not in sys.path:
        sys.path.insert(0, path)

import credential_driver_pb2 as pb  # noqa: E402
import credential_driver_pb2_grpc as pb_grpc  # noqa: E402
import datamodel_pb2  # noqa: E402
import extension_pb2  # noqa: E402
from ss_driver.config import DriverConfig  # noqa: E402
from ss_driver.naming import NAME_PREFIX  # noqa: E402
from ss_driver.secret_server import SecretServerClient, SecretServerError  # noqa: E402

CONTRACT = "openshell.credentials.contract"
TEST_PREFIX = "openshell-itest-"
TEST_WORKSPACE = "openshell-itest"
results = []
not_run = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


def skip(name, reason):
    not_run.append(name)
    print(f"NOT RUN  {name}  [{reason}]")


def fail_setup(message):
    print(f"SETUP ERROR: {message}")
    sys.exit(2)


def platform_env():
    hostname = os.environ.get("PLATFORM_HOSTNAME", "").strip()
    account = os.environ.get("PLATFORM_SERVICE_ACCOUNT", "")
    password = os.environ.get("PLATFORM_SERVICE_PASSWORD", "")
    if not (hostname and account and password):
        fail_setup("PLATFORM_HOSTNAME, PLATFORM_SERVICE_ACCOUNT and PLATFORM_SERVICE_PASSWORD must be set; "
                   "run through live-test.sh --env-file <platform env file>")
    if "://" not in hostname:
        hostname = f"https://{hostname}"
    return {"SS_PLATFORM_HOSTNAME": hostname.rstrip("/"), "SS_CLIENT_ID": account,
            "SS_CLIENT_SECRET": password}, [password]


def client_for(base_url, env, folder_id=1, template_id=1, slug="password"):
    return SecretServerClient(DriverConfig(
        base_url=base_url, folder_id=folder_id, template_id=template_id, field_slug=slug,
        platform_hostname=env["SS_PLATFORM_HOSTNAME"], client_id=env["SS_CLIENT_ID"],
        client_secret=env["SS_CLIENT_SECRET"]))


def _usable_url(value):
    parsed = urlparse(value)
    loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    return parsed.scheme == "https" or (parsed.scheme == "http" and loopback)


def find_urls(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and "url" in key.lower() and _usable_url(value):
                found.append(value.rstrip("/"))
            else:
                find_urls(value, found)
    elif isinstance(node, list):
        for value in node:
            find_urls(value, found)


def discover_vault_url(env):
    platform = client_for(env["SS_PLATFORM_HOSTNAME"], env)
    try:
        listing = platform._call("GET", "/vaultbroker/api/vaults", "list Platform vaults")
    except SecretServerError as err:
        fail_setup(f"couldn't list the Platform tenant's vaults ({err}). Pass --vault-url with the Secret Server "
                   "URL of the vault connected to this Platform tenant, or set OPENSHELL_PLATFORM_VAULT_URL")
    urls = []
    find_urls(listing, urls)
    platform_host = urlparse(env["SS_PLATFORM_HOSTNAME"]).hostname
    urls = [u for u in dict.fromkeys(urls) if urlparse(u).hostname != platform_host]
    if not urls:
        fail_setup("the Platform vault listing has no Secret Server URL. Pass --vault-url or set "
                   "OPENSHELL_PLATFORM_VAULT_URL")
    if len(urls) > 1:
        print(f"      Platform lists {len(urls)} vault URLs; using the first. Pass --vault-url to choose another.")
    return urls[0], "discovered from the Platform vault listing"


def create_test_subfolder(client, folder_name, max_attempts=20):
    """Create the test folder inside the first visible folder that allows it.

    Only the new subfolder is ever written to; parent folders are untouched.
    """
    try:
        visible = client.list_folders()
    except SecretServerError as err:
        print(f"      can't list folders: {err}")
        return None
    try:
        owned = client.list_folders(permission="Owner")
    except SecretServerError:
        owned = []
    owned_ids = {int(f.get("id", 0)) for f in owned}
    if owned_ids and len(owned_ids) < len(visible):
        print(f"      the account owns {len(owned_ids)} of {len(visible)} visible folders; trying those first")
    def rank(folder):
        path = str(folder.get("folderPath") or folder.get("folderName") or "").lower()
        return (0 if int(folder.get("id", 0)) in owned_ids else 1, 0 if "personal" in path else 1,
                int(folder.get("id", 0)))
    folders = list({int(f.get("id", 0)): f for f in owned + visible}.values())
    attempts = 0
    for folder in sorted(folders, key=rank):
        parent = int(folder.get("id", 0))
        if parent <= 0 or str(folder.get("folderName", "")).startswith(TEST_PREFIX):
            continue
        if attempts >= max_attempts:
            break
        attempts += 1
        try:
            folder_id = client.create_folder(folder_name, parent)
        except SecretServerError:
            continue
        label = folder.get("folderPath") or folder.get("folderName") or parent
        owner_note = ", owned by the account" if parent in owned_ids else ""
        print(f"      created test folder '{folder_name}' inside '{label}'{owner_note} (id {folder_id}, "
              f"{attempts} of {len(folders)} visible folders tried)")
        return folder_id
    print(f"      no visible folder allows creating a subfolder ({attempts} of {len(folders)} tried)")
    return None


def gateway_metadata():
    return extension_pb2.PeerMetadata(
        protocol_version=extension_pb2.ProtocolVersion(major=1, minor=0),
        implementation_name="openshell/gateway", implementation_version="0.1.2",
        supported_capabilities=[CONTRACT], required_capabilities=[CONTRACT])


def stamped(handle):
    copy = datamodel_pb2.CredentialHandle()
    copy.CopyFrom(handle)
    copy.driver = "delinea-secret-server"
    return copy


def start_driver(child_env):
    workdir = tempfile.mkdtemp(prefix="ssd-live-")
    socket_path = os.path.join(workdir, "run", "driver.sock")
    log_path = os.path.join(workdir, "driver.log")
    log_file = open(log_path, "w")
    proc = subprocess.Popen([sys.executable, "-m", "ss_driver", "--bind-socket", socket_path],
                            cwd=ROOT, env=child_env, stdout=log_file, stderr=subprocess.STDOUT)
    stub = pb_grpc.CredentialDriverStub(grpc.insecure_channel(f"unix:{socket_path}"))
    caps = None
    deadline = time.time() + 20
    while time.time() < deadline and proc.poll() is None and caps is None:
        if os.path.exists(socket_path):
            try:
                caps = stub.GetCapabilities(pb.GetCredentialDriverCapabilitiesRequest(gateway=gateway_metadata()), timeout=5)
            except grpc.RpcError:
                time.sleep(0.2)
        else:
            time.sleep(0.2)
    return proc, stub, caps, log_file, log_path


def stop_driver(proc, log_file):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    log_file.close()


def remove_test_folder(client, folder_id, label):
    """Deactivate driver-managed secrets in a test folder, then delete the folder."""
    ok = True
    try:
        for secret_id in client.active_secret_ids(folder_id, NAME_PREFIX):
            client.deactivate_secret(secret_id)
            print(f"      {label}: deactivated test secret {secret_id}")
        client.delete_folder(folder_id)
        print(f"      {label}: deleted test folder {folder_id}")
    except SecretServerError as err:
        ok = False
        print(f"      {label}: couldn't fully remove test folder {folder_id}: {err}")
    return ok


def summary():
    passed = sum(1 for _, ok in results if ok)
    failed = len(results) - passed
    print(f"\nlive-verified against the Platform tenant: {passed} passed, {failed} failed, {len(not_run)} not run")
    for name in not_run:
        print(f"  not run: {name}")
    return 0 if failed == 0 and not not_run else 1


def run_writes(stub, setup, folder_id, template_id, slug, values):
    identity = dict(provider="openshell-itest", credential_key="ITEST_TOKEN", workspace=TEST_WORKSPACE,
                    provider_id=str(uuid.uuid4()))
    try:
        handle = stamped(stub.StoreCredential(pb.StoreCredentialRequest(value=values[0], **identity), timeout=30).handle)
    except grpc.RpcError as err:
        check("store creates a secret in the test folder", False, f"{err.code().name}: {err.details()}")
        return
    secret_id = int(handle.handle.split(":", 1)[1])
    secret = setup.get_secret(secret_id)
    stored = next((i.get("itemValue") for i in secret.get("items") or [] if i.get("slug") == slug), None)
    check("store creates a secret in the test folder", True, f"secret {secret_id}")
    check("secret has the managed name, folder and template",
          str(secret.get("name", "")).startswith(NAME_PREFIX) and int(secret.get("folderId", -1)) == folder_id
          and int(secret.get("secretTemplateId", -1)) == template_id)
    check("the vault holds the stored value",
          stored == values[0] or setup.get_field(secret_id, slug) == values[0],
          "value in secret model" if stored is not None else "value from field endpoint")

    def resolve(ident=None):
        return stub.ResolveCredentials(pb.ResolveCredentialsRequest(credentials=[
            pb.ResolveCredentialRequest(request_id="live", handle=handle, **(ident or identity))]),
            timeout=30).credentials[0].value

    timings, value = [], None
    for _ in range(5):
        started = time.time()
        value = resolve()
        timings.append((time.time() - started) * 1000)
    check("resolve returns the stored value", value == values[0], f"median {statistics.median(timings):.0f} ms")
    updated = stub.StoreCredential(pb.StoreCredentialRequest(value=values[1], existing_handle=handle, **identity),
                                   timeout=30).handle
    check("update through existing_handle changes the value in place",
          updated.handle == handle.handle and resolve() == values[1])
    retried = stub.StoreCredential(pb.StoreCredentialRequest(value=values[2], **identity), timeout=30).handle
    check("a retried store reuses the managed secret", retried.handle == handle.handle and resolve() == values[2])
    try:
        resolve(dict(identity, provider_id=str(uuid.uuid4())))
        check("a handle replayed under another provider is refused", False, "resolved")
    except grpc.RpcError as err:
        check("a handle replayed under another provider is refused",
              err.code() == grpc.StatusCode.INVALID_ARGUMENT, err.code().name)
    stub.DeleteCredential(pb.DeleteCredentialRequest(handle=handle, **identity), timeout=30)
    try:
        deactivated = setup.get_secret(secret_id).get("active") is False
        detail = "readable with active=false"
    except SecretServerError as err:
        deactivated, detail = True, f"no longer readable (HTTP {err.status})"
    check("delete deactivates the secret", deactivated, detail)
    try:
        resolve()
        check("a deleted credential no longer resolves", False, "resolved")
    except grpc.RpcError as err:
        check("a deleted credential no longer resolves", True, err.code().name)
    try:
        stub.DeleteCredential(pb.DeleteCredentialRequest(handle=handle, **identity), timeout=30)
        check("deleting twice is a no-op", True)
    except grpc.RpcError as err:
        check("deleting twice is a no-op", False, f"{err.code().name}: {err.details()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--vault-url", default=os.environ.get("OPENSHELL_PLATFORM_VAULT_URL"))
    parser.add_argument("--parent-folder-id", type=int, default=-1,
                        help="create the openshell-itest-<timestamp> folder inside this folder")
    parser.add_argument("--template-id", type=int)
    parser.add_argument("--template-name", default="Password")
    parser.add_argument("--field-slug", default="password")
    args = parser.parse_args()

    if os.environ.get("DELINEA_PASSWORD") or os.environ.get("DELINEA_USERNAME"):
        fail_setup("DELINEA_* (standalone Secret Server) credentials are loaded; run through live-test.sh, "
                   "which loads only the Platform env file")
    env, secret_strings = platform_env()
    print(f"platform: {urlparse(env['SS_PLATFORM_HOSTNAME']).hostname}")
    if args.vault_url:
        vault_url, source = args.vault_url.rstrip("/"), "--vault-url"
    else:
        vault_url, source = discover_vault_url(env)
    print(f"vault: {urlparse(vault_url).hostname} ({source})\n")

    setup = client_for(vault_url, env)
    try:
        setup.find_folder_id("openshell-auth-probe")
    except SecretServerError as err:
        fail_setup(f"the vault rejected the Platform service account's token: {err}")
    check("the vault accepts the Platform service account's token", True)

    try:
        template_id = args.template_id or setup.find_template_id(args.template_name)
    except SecretServerError as err:
        fail_setup(f"template lookup failed: {err}")
    if not template_id:
        fail_setup(f"no template named '{args.template_name}'; pass --template-id")

    # Sweep leftovers from crashed runs, then create this run's folder.
    for folder in setup.folders_with_prefix(TEST_PREFIX):
        remove_test_folder(setup, int(folder["id"]), "pre-run sweep")
    folder_id = None
    folder_name = f"{TEST_PREFIX}{int(time.time())}"
    try:
        folder_id = setup.create_folder(folder_name, args.parent_folder_id)
        where = f"under folder {args.parent_folder_id}" if args.parent_folder_id > 0 else "at the vault root"
        print(f"      created test folder '{folder_name}' {where} (id {folder_id})")
    except SecretServerError as err:
        print(f"      can't create a test folder {'under ' + str(args.parent_folder_id) if args.parent_folder_id > 0 else 'at the vault root'}: {err}")
        if args.parent_folder_id <= 0:
            folder_id = create_test_subfolder(setup, folder_name)

    values = ["itest-" + pysecrets.token_hex(16) for _ in range(3)]
    config_folder = folder_id or 1
    child_env = dict(os.environ, PYTHONPATH=ROOT, SS_BASE_URL=vault_url, SS_FOLDER_ID=str(config_folder),
                     SS_TEMPLATE_ID=str(template_id), SS_FIELD_SLUG=args.field_slug, **env)
    for key in ("DELINEA_USERNAME", "DELINEA_USER", "DELINEA_PASSWORD", "DELINEA_BASE_URL"):
        child_env.pop(key, None)
    proc, stub, caps, log_file, log_path = start_driver(child_env)
    try:
        check("driver starts and completes the gateway handshake", caps is not None)
        if caps is None:
            return summary()
        if folder_id:
            try:
                slugs = setup.template_slugs(template_id, folder_id)
                check("template has the configured secret field", args.field_slug in slugs, ", ".join(slugs))
            except SecretServerError as err:
                check("template has the configured secret field", False, str(err))
            run_writes(stub, client_for(vault_url, env, folder_id, template_id, args.field_slug),
                       folder_id, template_id, args.field_slug, values)
        else:
            skip("write path: store, resolve, update, retry, replay refusal, delete",
                 "the service account can't create a test folder anywhere in the vault; give it Owner "
                 "(or Add Secret + Edit) on one folder and pass --parent-folder-id <id>")
            identity = dict(provider="openshell-itest", credential_key="ITEST_TOKEN", workspace=TEST_WORKSPACE,
                            provider_id=str(uuid.uuid4()))
            missing = datamodel_pb2.CredentialHandle(driver="delinea-secret-server", handle="v1:2147483000",
                                                     metadata={"object_id": identity["provider_id"]})
            try:
                stub.ResolveCredentials(pb.ResolveCredentialsRequest(credentials=[
                    pb.ResolveCredentialRequest(request_id="ro", handle=missing, **identity)]), timeout=30)
                check("resolving a handle to a missing secret fails cleanly", False, "value returned")
            except grpc.RpcError as err:
                check("resolving a handle to a missing secret fails cleanly",
                      err.code() in (grpc.StatusCode.NOT_FOUND, grpc.StatusCode.PERMISSION_DENIED),
                      f"{err.code().name}: {err.details()}")
    finally:
        stop_driver(proc, log_file)
        if folder_id:
            remove_test_folder(setup, folder_id, "cleanup")

    with open(log_path) as handle:
        log_text = handle.read()
    for line in log_text.splitlines():
        if "using Secret Server site" in line or "site listing unavailable" in line:
            print(f"      driver: {line.split(': ', 1)[-1]}")
    check("driver log contains no secret values or credentials",
          not any(v and v in log_text for v in values + secret_strings), f"{len(log_text.splitlines())} log lines")
    print(f"driver log (no secrets): {log_path}")
    return summary()


if __name__ == "__main__":
    sys.exit(main())
