# Delinea Secret Server credential driver for NVIDIA OpenShell

An [OpenShell](https://github.com/NVIDIA/OpenShell) **credential driver** that stores and resolves
the gateway's provider credentials (API keys, tokens) in **Delinea Secret Server**, including the
Secret Server vault behind a **Delinea Platform** tenant, instead of the gateway's built-in
encrypted database store.

OpenShell supports external credential drivers over a local gRPC socket (`transport = "uds"`), so
this runs next to an unmodified OpenShell gateway. It implements
`openshell.credentials.v1.CredentialDriver` (see `proto/`).

**Status:** proof of concept. Live-verified against a Delinea Platform tenant (14/14 live checks)
and 31/31 checks against a mock Secret Server.

## How it works

```
OpenShell gateway ──gRPC over Unix socket──> this driver ──HTTPS REST──> Secret Server
  (provider records keep only handles)         (no secrets on disk)       (vault, audit, rotation)
```

| OpenShell call | What the driver does in Secret Server |
|---|---|
| `GetCapabilities` | Protocol negotiation (major version 1, `openshell.credentials.contract`). |
| `StoreCredential` | Creates one secret per credential in a dedicated folder, or updates its field when the gateway passes an existing handle. |
| `ResolveCredentials` | Reads each secret, checks it is the managed secret for that exact provider and key, and returns the field value. |
| `DeleteCredential` | Deactivates the secret (Secret Server soft delete). |
| `ListCredentials` | Returns `UNIMPLEMENTED`. |

- **Handle:** `v1:<secret id>`, plus `object_id` metadata. The gateway stores only this.
- **Secret name:** `openshell-<first 40 hex of sha256(workspace, provider id, provider, key, object id)>`.
  Every resolve, update and delete re-checks name and folder, so a handle can't be replayed under
  another provider or key, or pointed at a secret outside the managed folder.
- **Refresh writes** with a new `object_id` get their own secret, so a staged value never
  overwrites the committed one. **Retries** after a partial failure reuse the managed secret.
- **Deactivated secrets** that the server still returns (`active: false`) are treated as deleted.

## Sign-in

- **Delinea Platform service account:** `platform_hostname`, `client_id`, `client_secret`
  (or `client_secret_file`). Client-credentials grant at
  `/identity/api/oauth2/token/xpmplatform`, scope `xpmheadless`.
- **Secret Server application account:** `username`, `password` (or `password_file`), OAuth2
  password grant.
- **Bearer token:** `bearer_token` (or `bearer_token_file`), no renewal.

## Set up

```bash
./setup.sh          # venv, dependencies, gRPC stubs from proto/
.venv/bin/python tests/e2e_test.py
```

Configure the gateway with `examples/gateway.toml` and the driver with
`examples/driver-config.json`. Every setting can also come from an `SS_*` environment variable
(`SS_BASE_URL`, `SS_FOLDER_ID`, `SS_TEMPLATE_ID`, `SS_FIELD_SLUG`, `SS_SITE_ID`,
`SS_PLATFORM_HOSTNAME`, `SS_CLIENT_ID`, `SS_CLIENT_SECRET_FILE`, `SS_USERNAME`,
`SS_PASSWORD_FILE`, `SS_CA_BUNDLE`, ...).

In Secret Server:

1. Create a folder for OpenShell-managed secrets and give the driver's account Owner on it.
2. Use a template with a password-type field (slug `password` by default). A `notes` field, if
   present, gets non-secret context: workspace, provider and key.
3. Don't enable checkout, approval or comment requirements on that folder; the gateway resolves
   credentials unattended.
4. Set `site_id` if you know it; otherwise the driver discovers one (see below).

## Behavior learned from a real Platform tenant

- The Secret Server vault behind a Platform tenant is listed at `/vaultbroker/api/vaults` and
  accepts the Platform service account's token.
- Creating a secret needs the minimal body: name, template, folder, site and `{fieldId, itemValue}`
  items. Posting the full stub back is rejected with "The request is invalid."
- `siteId` is required and must be 1 or higher; stubs return 0. Unless `site_id` is set, the driver
  uses the first active distributed-engine site, else the site of a secret the account can see.
- A missing secret returns HTTP 400 `API_AccessDenied`, not 404, so "gone" and "no permission"
  look the same to the driver.
- Deactivated secrets stay readable with `active: false`.
- A service account may not be allowed to create root folders; pre-create the driver's folder.
- A resolve takes about 380 ms against Secret Server Cloud; batch resolves are sequential today.

## Tests

- `tests/e2e_test.py` launches the driver the way the gateway does (`--bind-socket`), repeats the
  gateway's readiness and negotiation rules, and runs the contract against `tests/mock_secret_server.py`:
  store, batch resolve, update, retry, staged refresh, rotation inside Secret Server, replay and
  forged-handle refusal, session expiry, delete, audit trail, both sign-in modes and log hygiene.
- `live-test.sh --env-file <file>` runs the mock suite first, then `tests/live_tenant_test.py`
  against a Delinea Platform tenant with only that env file loaded (it must export
  `PLATFORM_HOSTNAME`, `PLATFORM_SERVICE_ACCOUNT` and `PLATFORM_SERVICE_PASSWORD`). The live test
  creates an `openshell-itest-<timestamp>` folder (inside a folder the account owns if the root is
  refused), stores only random test values, deletes everything in `finally`, and sweeps leftover
  `openshell-itest-` folders at the start. It reports passed, failed and not-run separately and
  prints no credentials. Pass `--vault-url` if the vault listing isn't available.
- `tests/run_mock_server.py` runs the mock standalone for dry runs.

## Security choices

- TLS certificate and hostname verification are always on. Private CAs go in `ca_bundle`; there
  is no verification bypass. `http://` is accepted only for loopback addresses.
- The socket is created owner-only in an owner-only directory. The driver refuses to replace a
  path that isn't a socket, is a symlink, or belongs to another user.
- Secret values and tokens are never logged or put into error messages.

## Known limits

1. OpenShell's design moves the resolved value into the gateway and the sandbox supervisor's
   memory. Secret Server holds it at rest and audits every read.
2. When a running sandbox picks up a value rotated in Secret Server depends on when the gateway
   re-resolves credentials.
3. `ListCredentials` isn't implemented.
4. Folders with checkout, approval or comment policies aren't supported for unattended resolves.
5. Python keeps the proof of concept short; a production driver would likely be Go or Rust.
