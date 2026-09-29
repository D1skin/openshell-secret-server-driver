#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
#
# Demo harness: a real OpenShell gateway using Delinea Secret Server as its credential store.
#
#   demo/demo.sh up --env-file <platform.env> [--vault-url https://...]   # real Platform vault
#   demo/demo.sh up --mock                                                # mock Secret Server
#   demo/demo.sh api                                                      # the Acme Orders API (foreground)
#   demo/demo.sh gateway-db                                               # what the gateway stores
#   demo/demo.sh security rotate|revoke|restore|audit                     # mock mode: play security
#   demo/demo.sh status
#   demo/demo.sh down [--purge]
#
# The env file must define PLATFORM_HOSTNAME, PLATFORM_SERVICE_ACCOUNT and
# PLATFORM_SERVICE_PASSWORD. Only those three values are read, in a clean subshell, and
# they reach the gateway (and the driver it launches) through the environment, never disk.
# Tested on macOS (Apple Silicon) with Docker Desktop.
set -euo pipefail
trap 'printf "error: demo.sh failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
DEMO_HOME="${DEMO_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/openshell-secret-server-demo}"
OPENSHELL_VERSION="${OPENSHELL_VERSION:-v0.1.2}"
PORT="${DEMO_GATEWAY_PORT:-17690}"
API_PORT=18099
SANDBOX_IMAGE="nvcr.io/nvidia/base/ubuntu:24.04"
AGENT_IMAGE="${DEMO_AGENT_IMAGE:-openshell-demo-claude:2.1.284}"

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

openshell_cli() {
  XDG_CONFIG_HOME="$DEMO_HOME/xdg-config" XDG_STATE_HOME="$DEMO_HOME/xdg-state" \
    OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:$PORT" "$DEMO_HOME/bin/openshell" "$@"
}

download_openshell() {
  [ -x "$DEMO_HOME/bin/openshell" ] && [ -x "$DEMO_HOME/bin/openshell-gateway" ] && return
  [ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || die "this demo downloads macOS arm64 builds; install OpenShell into $DEMO_HOME/bin yourself"
  local base="https://github.com/NVIDIA/OpenShell/releases/download/$OPENSHELL_VERSION" dl="$DEMO_HOME/dl"
  mkdir -p "$dl"
  say "downloading OpenShell $OPENSHELL_VERSION (CLI and gateway, ~40 MB)"
  for f in openshell-checksums-sha256.txt openshell-gateway-checksums-sha256.txt \
           openshell-aarch64-apple-darwin.tar.gz openshell-gateway-aarch64-apple-darwin.tar.gz; do
    curl -fLsS --retry 3 -o "$dl/$f" "$base/$f"
  done
  for f in openshell-aarch64-apple-darwin.tar.gz openshell-gateway-aarch64-apple-darwin.tar.gz; do
    want="$(awk -v f="$f" '$2==f || $2=="*"f {print $1; exit}' "$dl"/openshell-*checksums-sha256.txt)"
    got="$(shasum -a 256 "$dl/$f" | awk '{print $1}')"
    [ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $f"
    tar -xzf "$dl/$f" -C "$DEMO_HOME/bin"
  done
  say "OpenShell binaries verified against NVIDIA's published SHA-256 checksums"
}

make_jwt_keys() {
  [ -f "$DEMO_HOME/jwt/signing.pem" ] && return
  local ssl
  for ssl in /opt/homebrew/opt/openssl@3/bin/openssl openssl; do
    if "$ssl" genpkey -algorithm ed25519 -out "$DEMO_HOME/jwt/signing.pem" 2>/dev/null; then
      "$ssl" pkey -in "$DEMO_HOME/jwt/signing.pem" -pubout -out "$DEMO_HOME/jwt/public.pem"
      break
    fi
  done
  if [ ! -s "$DEMO_HOME/jwt/public.pem" ]; then
    uv run --quiet --with cryptography python - "$DEMO_HOME/jwt" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
out = sys.argv[1]
open(f"{out}/signing.pem", "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open(f"{out}/public.pem", "wb").write(key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
PY
  fi
  chmod 600 "$DEMO_HOME/jwt/signing.pem"
  printf 'openshell-demo-key' > "$DEMO_HOME/jwt/kid"
}

load_platform_credentials() {
  local env_file="$1" assignments
  [ -f "$env_file" ] || die "env file not found: $env_file"
  # Read only the three Platform values, in a clean environment.
  assignments="$(env -i HOME="$HOME" bash -c 'set -a; source "$1" >/dev/null 2>&1; set +a
    printf "SS_PLATFORM_HOSTNAME=%q\nSS_CLIENT_ID=%q\nSS_CLIENT_SECRET=%q\n" \
      "${PLATFORM_HOSTNAME:-}" "${PLATFORM_SERVICE_ACCOUNT:-}" "${PLATFORM_SERVICE_PASSWORD:-}"' _ "$env_file")"
  eval "$assignments"
  [ -n "$SS_PLATFORM_HOSTNAME" ] && [ -n "$SS_CLIENT_ID" ] && [ -n "$SS_CLIENT_SECRET" ] \
    || die "$env_file must define PLATFORM_HOSTNAME, PLATFORM_SERVICE_ACCOUNT and PLATFORM_SERVICE_PASSWORD"
  export SS_PLATFORM_HOSTNAME SS_CLIENT_ID SS_CLIENT_SECRET
}

start_mock() {
  ( cd "$repo" || exit 1
    nohup uv run --quiet python -u "$repo/tests/run_mock_server.py" > "$DEMO_HOME/logs/mock.log" 2>&1 < /dev/null &
    echo $! > "$DEMO_HOME/run/mock.pid" )
  for _ in $(seq 1 40); do grep -q '^http' "$DEMO_HOME/logs/mock.log" 2>/dev/null && break; sleep 0.25; done
  local url; url="$(head -1 "$DEMO_HOME/logs/mock.log")"
  [[ "$url" == http* ]] || die "mock Secret Server did not start; see $DEMO_HOME/logs/mock.log"
  # The platform host must differ from the vault host for vault discovery.
  export SS_PLATFORM_HOSTNAME="http://localhost:${url##*:}" SS_CLIENT_ID="mock-svc" SS_CLIENT_SECRET="mock-client-secret"
  MOCK_URL="$url"
  say "mock Secret Server at $url"
}

cmd_up() {
  local env_file="" mock=0 vault_url="" MOCK_URL=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --env-file) env_file="${2:-}"; shift 2 ;;
      --mock) mock=1; shift ;;
      --vault-url) vault_url="${2:-}"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ "$mock" = 1 ] || [ -n "$env_file" ] || die "pass --env-file <platform.env> or --mock"
  command -v uv >/dev/null || die "uv is required (https://docs.astral.sh/uv/)"
  docker info >/dev/null 2>&1 || die "Docker is not running"
  [ -f "$DEMO_HOME/run/gateway.pid" ] && kill -0 "$(cat "$DEMO_HOME/run/gateway.pid")" 2>/dev/null \
    && die "the demo is already up; run 'demo/demo.sh down' first"
  mkdir -p "$DEMO_HOME"/{bin,logs,run,jwt,config,xdg-config,xdg-state,tools}

  download_openshell
  if ! docker image inspect "$AGENT_IMAGE" >/dev/null 2>&1; then
    say "building the agent image $AGENT_IMAGE (Claude Code + curl)"
    docker build -q -t "$AGENT_IMAGE" "$here/agent-image" >/dev/null
  fi
  say "installing the driver from this checkout as a uv tool"
  UV_TOOL_DIR="$DEMO_HOME/tools" UV_TOOL_BIN_DIR="$DEMO_HOME/tools/bin" uv tool install --quiet --force "$repo"
  make_jwt_keys

  if [ "$mock" = 1 ]; then start_mock; else load_platform_credentials "$env_file"; fi
  [ -n "$vault_url" ] && export SS_BASE_URL="$vault_url"
  say "preparing the vault (template, the driver's folder, the security team's folder and secret)"
  local setup; setup="$(cd "$repo" && uv run --quiet python demo/vault_setup.py)"
  eval "$setup"
  # The driver may read existing secrets only from the security team's folder.
  cat > "$DEMO_HOME/config/driver.json" <<EOF
{"base_url": "$VAULT_URL", "folder_id": $FOLDER_ID, "template_id": $TEMPLATE_ID, "field_slug": "password",
 "reference_folder_ids": [$SECURITY_FOLDER_ID]}
EOF

  local grpc_endpoint=""
  if [ "$(uname -s)" = "Darwin" ]; then
    # Docker Desktop: supervisors reach the Mac through host.docker.internal's IP.
    local host_ip
    host_ip="$(docker run --rm --entrypoint getent "$SANDBOX_IMAGE" ahostsv4 host.docker.internal | awk '{ if (!ip) ip = $1 } END { print ip }')"
    [ -n "$host_ip" ] || die "could not resolve host.docker.internal from a container"
    grpc_endpoint="grpc_endpoint = \"http://$host_ip:$PORT\""
  fi
  cat > "$DEMO_HOME/config/gateway.toml" <<EOF
# Throwaway demo gateway on 127.0.0.1 only. Not for shared use.
[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"
credential_drivers = ["delinea-secret-server"]
log_level = "info"

[openshell.gateway.gateway_jwt]
signing_key_path = "$DEMO_HOME/jwt/signing.pem"
public_key_path = "$DEMO_HOME/jwt/public.pem"
kid_path = "$DEMO_HOME/jwt/kid"
gateway_id = "openshell-demo"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.drivers.docker]
sandbox_label = "openshell-ss-demo"
$grpc_endpoint

[openshell.credential_drivers.delinea-secret-server]
transport = "uds"
socket_path = "$DEMO_HOME/run/driver.sock"
command = "$DEMO_HOME/tools/bin/openshell-secret-server-driver"
args = ["--config", "$DEMO_HOME/config/driver.json"]
startup_timeout_secs = 30
EOF

  say "starting the OpenShell gateway on 127.0.0.1:$PORT"
  ( cd "$DEMO_HOME" || exit 1
    XDG_CONFIG_HOME="$DEMO_HOME/xdg-config" XDG_STATE_HOME="$DEMO_HOME/xdg-state" \
      nohup "$DEMO_HOME/bin/openshell-gateway" --config "$DEMO_HOME/config/gateway.toml" --disable-tls \
        --bind-address 127.0.0.1 --port "$PORT" > "$DEMO_HOME/logs/gateway.log" 2>&1 < /dev/null &
    echo $! > "$DEMO_HOME/run/gateway.pid" )
  local out=""
  for _ in $(seq 1 60); do
    out="$(openshell_cli status 2>/dev/null || true)"
    [[ "$out" == *Connected* ]] && break
    sleep 0.5
  done
  out="$(openshell_cli gateway info 2>/dev/null || true)"
  [[ "$out" == *delinea-secret-server* ]] \
    || { tail -20 "$DEMO_HOME/logs/gateway.log" >&2; die "the gateway did not load the Secret Server driver"; }
  say "gateway is using Delinea Secret Server as its credential store"

  for profile in acme-orders claude-code; do
    openshell_cli provider profile describe "$profile" >/dev/null 2>&1 \
      || openshell_cli provider profile import -f "$here/profiles/$profile.yaml" >/dev/null
  done
  say "warming up (pulls the sandbox images on first run)"
  openshell_cli sandbox create --name demo-warmup --from "$AGENT_IMAGE" --no-auto-providers --no-keep --no-tty -- true >/dev/null 2>&1 || true
  { printf 'MODE=%s\n' "$([ "$mock" = 1 ] && echo mock || echo platform)"
    printf 'ORDERS_SECRET_ID=%s\nSECURITY_FOLDER_ID=%s\nMOCK_URL=%s\n' "$ORDERS_SECRET_ID" "$SECURITY_FOLDER_ID" "$MOCK_URL"
  } > "$DEMO_HOME/run/demo.env"
  say "security's Orders API key is secret $ORDERS_SECRET_ID; OpenShell may read only from folder $SECURITY_FOLDER_ID"
  say "ready. In each demo terminal: cd $repo && source demo/env.sh"
}

cmd_api() { exec python3 "$here/orders_api.py" "$API_PORT"; }

load_demo_env() {
  [ -f "$DEMO_HOME/run/demo.env" ] || die "the demo isn't up; run 'demo/demo.sh up' first"
  # shellcheck disable=SC1091
  . "$DEMO_HOME/run/demo.env"
}

cmd_gateway_db() {
  # Read-only look at the gateway's own database: which credential handles it
  # keeps per provider, and whether any API key made it to disk.
  local db="$DEMO_HOME/xdg-state/openshell/gateway/openshell.db" name hex handles copies
  [ -f "$db" ] || die "no gateway database yet; run 'demo/demo.sh up' first"
  printf '\033[2m$ sqlite3 -readonly %s\033[0m\n' "~${db#"$HOME"}"
  echo "Credentials the OpenShell gateway stores, per provider:"
  while IFS='|' read -r name hex; do
    handles="$(printf '%s' "$hex" | xxd -r -p | LC_ALL=C grep -a -Eo 'ref1:[0-9]+/[A-Za-z0-9_.-]+|v1:[0-9]+' | sort -u | paste -s -d ' ' - || true)"
    printf '  %-12s %s\n' "$name" "${handles:-(none)}"
  done < <(sqlite3 -readonly "$db" "select name, hex(payload) from objects where object_type = 'provider' order by name")
  copies="$(cat "$db" "$db-wal" 2>/dev/null | LC_ALL=C grep -a -o -E 'acme_live_|sk-ant-' | wc -l | tr -d ' ' || true)"
  echo "API keys in the gateway's database files: ${copies:-0}"
}

mock_call() { curl -fsS -X POST -H 'Content-Type: application/json' -d "$2" "$MOCK_URL$1" >/dev/null; }

cmd_security() {
  load_demo_env
  [ "$MODE" = mock ] || die "with a real vault, play the security team in the Secret Server UI (see demo/README.md)"
  local value
  case "${1:-}" in
    rotate)
      value="${2:-$(python3 -c 'import secrets, string; print("acme_live_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10)))')}"
      mock_call "/_test/rotate/$ORDERS_SECRET_ID" "{\"value\": \"$value\"}"
      say "security rotated the Orders API key (secret $ORDERS_SECRET_ID) in Secret Server" ;;
    revoke)
      mock_call "/_test/secret-flags/$ORDERS_SECRET_ID" '{"active": false}'
      say "security deactivated the Orders API key (secret $ORDERS_SECRET_ID)" ;;
    restore)
      mock_call "/_test/secret-flags/$ORDERS_SECRET_ID" '{"active": true}'
      say "security reactivated the Orders API key (secret $ORDERS_SECRET_ID)" ;;
    audit)
      echo "Secret Server audit for secret $ORDERS_SECRET_ID:"
      curl -fsS "$MOCK_URL/_test/audit" | python3 -c '
import json, sys, time
secret_id = int(sys.argv[1])
for entry in json.load(sys.stdin):
    if entry["secretId"] == secret_id:
        when = time.strftime("%H:%M:%S", time.localtime(entry["at"]))
        print("  %s  %-8s %-14s %s" % (when, entry["action"], entry["user"], entry.get("notes") or ""))
' "$ORDERS_SECRET_ID" ;;
    *) die "usage: demo/demo.sh security rotate [new-key] | revoke | restore | audit" ;;
  esac
}

cmd_status() {
  openshell_cli status 2>&1 | grep -E "Status|Version" || true
  openshell_cli gateway info 2>&1 | grep -A1 "delinea-secret-server" || echo "driver not loaded"
}

cmd_down() {
  local purge=0; [ "${1:-}" = "--purge" ] && purge=1
  if [ -x "$DEMO_HOME/bin/openshell" ] && openshell_cli status >/dev/null 2>&1; then
    for s in $(openshell_cli sandbox list 2>/dev/null | awk 'NR>1 {print $1}'); do openshell_cli sandbox delete "$s" >/dev/null 2>&1 || true; done
    local providers; providers="$(openshell_cli provider list 2>/dev/null | awk 'NR>1 {print $1}' || true)"
    if grep -qx acme-orders <<<"$providers"; then
      openshell_cli provider delete acme-orders >/dev/null 2>&1 \
        && say "deleted provider acme-orders (detached; the security team's secret is unchanged)" || true
    fi
    if grep -qx claude <<<"$providers"; then
      openshell_cli provider delete claude >/dev/null 2>&1 \
        && say "deleted provider claude (the key it stored is deactivated in the vault)" || true
    fi
    sleep 2
  fi
  for p in gateway mock; do
    [ -f "$DEMO_HOME/run/$p.pid" ] && kill "$(cat "$DEMO_HOME/run/$p.pid")" 2>/dev/null || true
    rm -f "$DEMO_HOME/run/$p.pid"
  done
  pkill -f "orders_api.py $API_PORT" 2>/dev/null || true
  pkill -f "$repo/tests/run_mock_server.py" 2>/dev/null || true
  say "demo stopped"
  if [ "$purge" = 1 ]; then rm -rf "$DEMO_HOME"; say "removed $DEMO_HOME"; fi
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  api) cmd_api ;;
  gateway-db) cmd_gateway_db ;;
  security) shift; cmd_security "$@" ;;
  status) cmd_status ;;
  down) shift; cmd_down "$@" ;;
  *) sed -n '5,14p' "$0"; exit 2 ;;
esac
