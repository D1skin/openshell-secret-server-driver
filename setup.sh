#!/usr/bin/env bash
# Create the virtual environment, install dependencies and generate the gRPC stubs.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
python3 -m venv "$here/.venv"
"$here/.venv/bin/pip" install --quiet -r "$here/requirements.txt"
"$here/gen_protos.sh"
