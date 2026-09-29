# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
# Source this in each demo terminal: points the openshell CLI at the demo gateway.
DEMO_HOME="${DEMO_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/openshell-secret-server-demo}"
export PATH="$DEMO_HOME/bin:$PATH"
export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:${DEMO_GATEWAY_PORT:-17690}"
export XDG_CONFIG_HOME="$DEMO_HOME/xdg-config" XDG_STATE_HOME="$DEMO_HOME/xdg-state"
export PS1='$ '
