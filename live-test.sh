#!/usr/bin/env bash
# Live test against a Delinea Platform tenant.
#   1. The mocked suite must pass first; a live failure on top of a mock failure is noise.
#   2. Only the Platform env file you pass is loaded, and standalone Secret Server
#      variables (DELINEA_*) are cleared, so the two credential spaces can't collide.
# Usage: ./live-test.sh --env-file /path/to/platform.env [live test options]
set -eo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
env_file=""
if [ "${1:-}" = "--env-file" ]; then env_file="${2:-}"; shift 2; fi
env_file="${env_file:-${PLATFORM_ENV_FILE:-}}"
if [ -z "$env_file" ] || [ ! -f "$env_file" ]; then
  echo "usage: $0 --env-file <file exporting PLATFORM_HOSTNAME, PLATFORM_SERVICE_ACCOUNT, PLATFORM_SERVICE_PASSWORD>"
  exit 2
fi

unit_log="$(mktemp -t ssd-unit)"
if ! "$here/.venv/bin/python" "$here/tests/e2e_test.py" >"$unit_log" 2>&1; then
  echo "mock suite failed; not running live tests. Output: $unit_log"
  tail -5 "$unit_log"
  exit 1
fi
echo "mock suite: $(tail -1 "$unit_log")"
echo

unset DELINEA_USERNAME DELINEA_USER DELINEA_PASSWORD DELINEA_BASE_URL
set -a
# shellcheck disable=SC1090
source "$env_file"
set +a
exec "$here/.venv/bin/python" "$here/tests/live_tenant_test.py" "$@"
