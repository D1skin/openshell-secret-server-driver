# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
# Source this in each demo terminal: points the openshell CLI at the demo gateway.
DEMO_HOME="${DEMO_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/openshell-secret-server-demo}"
export PATH="$DEMO_HOME/bin:$PATH"
export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:${DEMO_GATEWAY_PORT:-17690}"
export XDG_CONFIG_HOME="$DEMO_HOME/xdg-config" XDG_STATE_HOME="$DEMO_HOME/xdg-state"
export PS1='$ '
# The ID of the security team's Orders API key, so you can type secretserver:$ORDERS_SECRET_ID.
ORDERS_SECRET_ID="$(sed -n 's/^ORDERS_SECRET_ID=//p' "$DEMO_HOME/run/demo.env" 2>/dev/null)"
export ORDERS_SECRET_ID
