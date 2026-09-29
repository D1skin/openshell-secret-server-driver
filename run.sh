#!/usr/bin/env bash
# Wrapper for the gateway's `command` setting. The gateway appends --bind-socket <socket_path>.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
exec "$here/.venv/bin/python" -m ss_driver "$@"
