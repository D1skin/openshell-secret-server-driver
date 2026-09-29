# Demo: Acme's refund agent

Acme's support team uses **Claude Code** to triage refund requests. To look up orders it needs
Acme's production **Orders API key**, which security keeps in **Delinea Secret Server**. The agent
runs in an **OpenShell** sandbox whose gateway uses this driver as its credential store, so:

1. The key is registered once and lives in Secret Server, next to everything else security governs.
2. Claude uses the key to do its job, yet only ever holds a placeholder.
3. A prompt-injected agent has nothing real to steal, and can't reach an attacker's host anyway.
4. Security rotates the key in Secret Server; the agent's next run just works.
5. Every read is in Secret Server's audit trail, and deactivating the secret cuts the agent off.

Claude's own Anthropic API key is stored in Secret Server the same way.

## Prerequisites

macOS on Apple Silicon with Docker Desktop, [uv](https://docs.astral.sh/uv/), and a Delinea
Platform service account that can create a folder (or owns one). `up` downloads OpenShell v0.1.2
(checksum-verified), builds the agent image and warms everything up, so nothing downloads on camera.

```bash
demo/demo.sh up --env-file /path/to/platform.env   # or: demo/demo.sh up --mock
```

The env file must export `PLATFORM_HOSTNAME`, `PLATFORM_SERVICE_ACCOUNT` and
`PLATFORM_SERVICE_PASSWORD`. Only those three values are read, and they reach the gateway through
its environment, never disk. `up` creates or reuses an **OpenShell Agents** folder in the vault.

## Run it

Terminal B, the Orders API:

```bash
demo/demo.sh api
```

Terminal A, the story:

```bash
source demo/env.sh
openshell gateway info | grep -A1 delinea-secret-server              # the Delinea driver is loaded
openshell provider create --name claude --type claude-code --credential ANTHROPIC_API_KEY
openshell provider create --name acme-orders --type acme-orders --credential ORDERS_API_KEY=acme_live_7Hq2Rf9Xk
demo/ask.sh "Is order 1042 eligible for a refund?"                    # Claude answers; the API shows the real key
demo/attack.sh                                                        # placeholders only, exfiltration blocked
# rotate the Orders key in Secret Server, then ask again: the API shows the new key
demo/ask.sh "What about order 1043?"
# deactivate the secret in Secret Server, then ask again: the agent can't get the key
demo/ask.sh "Is order 1042 eligible for a refund?"
```

`--credential ANTHROPIC_API_KEY` without a value reads it from your shell, so export
`ANTHROPIC_API_KEY` beforehand and it never appears on screen.

## Clean up

```bash
demo/demo.sh down          # deletes the providers (their secrets are deactivated) and stops everything
demo/demo.sh down --purge  # also removes the demo's cached binaries and state
```

The **OpenShell Agents** folder stays in the vault; delete it in Secret Server if you don't need it.
