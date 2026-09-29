#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
# Generate Python gRPC stubs from the vendored OpenShell protocol files in proto/.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/generated"
mkdir -p "$out"
"$here/.venv/bin/python" -m grpc_tools.protoc \
  -I "$here/proto" \
  --python_out="$out" \
  --grpc_python_out="$out" \
  "$here/proto/credential_driver.proto" \
  "$here/proto/datamodel.proto" \
  "$here/proto/extension.proto" \
  "$here/proto/options.proto"
echo "generated stubs in $out"
