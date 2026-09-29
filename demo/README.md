# Demo: Acme's refund agent

Acme's support team uses **Claude Code** to triage refund requests. To look orders up, it needs
Acme's production **Orders API key**. That key belongs to Acme's **security team**. It lives in
their **Acme Production** folder in **Delinea Secret Server**, they rotate it, and they decide who
can use it. The agent runs in an **OpenShell** sandbox whose gateway uses this driver as its
credential store.

What the demo shows:

1. **Security keeps ownership.** The platform engineer attaches the key by its Secret Server ID
   (`secretserver:<id>`). They never see it, and OpenShell stores a pointer, not a copy.
2. **The agent never holds the key.** Claude does its job with a placeholder. The real key is added
   on the way out, only on requests to the Orders API.
3. **Every read is on the record.** The secret's audit trail in Secret Server shows each read by
   OpenShell, tagged with the provider and credential that asked for it.
4. **Security stays in control.** A rotation in Secret Server reaches the next run with no change in
   OpenShell. Deactivating the secret cuts the agent off. Deleting the provider only detaches it.
5. **Optional: a hijacked agent finds nothing to steal**, and can't reach an attacker's host.

Claude's own Anthropic API key shows the other mode: a value you hand to OpenShell is stored by the
driver in Secret Server, in the **OpenShell Agents** folder.

## Prerequisites

macOS on Apple Silicon with Docker Desktop, [uv](https://docs.astral.sh/uv/), and a Delinea
Platform service account. `up` downloads OpenShell v0.1.2 (checksum-verified), builds the agent
image and warms everything up, so nothing downloads on camera.

```bash
demo/demo.sh up --env-file /path/to/platform.env   # or: demo/demo.sh up --mock
```

The env file must export `PLATFORM_HOSTNAME`, `PLATFORM_SERVICE_ACCOUNT` and
`PLATFORM_SERVICE_PASSWORD`. Only those three values are read, and they reach the gateway through
its environment, never disk.

`up` prepares two folders: **OpenShell Agents** (the driver's own) and **Acme Production** (the
security team's, holding the **Acme Orders API (production)** secret). Each is reused if it already
exists. The driver may read existing secrets only from Acme Production (`reference_folder_ids`).
For the most realistic run, create Acme Production and its secret yourself in Secret Server, give
the service account **View** on that folder and nothing more, and run `up`.

## Run it

Terminal B, the Orders API:

```bash
demo/demo.sh api
```

Terminal A, the story:

```bash
source demo/env.sh
openshell gateway info | grep -A1 delinea-secret-server       # the Delinea driver is loaded
openshell provider create --name claude --type claude-code --credential ANTHROPIC_API_KEY
openshell provider create --name acme-orders --type acme-orders --credential ORDERS_API_KEY=secretserver:$ORDERS_SECRET_ID
demo/demo.sh gateway-db                                       # pointers, not keys
demo/ask.sh "Is order 1042 eligible for a refund?"             # Claude answers; the API shows the key arrived
# Secret Server: open the secret's audit. OpenShell's reads are there, with provider and key.
# Secret Server: change the key (keep the acme_live_ prefix), then ask again:
demo/ask.sh "What about order 1043?"                           # the API shows the new key
# Secret Server: deactivate the secret, then ask again:
demo/ask.sh "Is order 1042 eligible for a refund?"             # the agent can't get the key
demo/attack.sh                                                 # optional: placeholders only, upload blocked
```

`--credential ANTHROPIC_API_KEY` without a value reads it from your shell, so export
`ANTHROPIC_API_KEY` beforehand and it never appears on screen. `$ORDERS_SECRET_ID` is the Acme
secret's ID (`env.sh` sets it); you can type the number instead.

With `--mock`, `demo/demo.sh security rotate | revoke | restore | audit` plays the security team.

Each `ask.sh` run starts a fresh sandbox. A sandbox that's already running keeps the value OpenShell
read when it started, so rotations and deactivations show up on the next run.

## Clean up

```bash
demo/demo.sh down          # deletes the providers: detaches Acme's secret, deactivates the key the driver stored
demo/demo.sh down --purge  # also removes the demo's cached binaries and state
```

Both folders and the Acme secret stay in the vault. Delete them in Secret Server if you don't need them.
