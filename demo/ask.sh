#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
# Ask Acme's refund agent (Claude Code in an OpenShell sandbox) about an order.
# Prints the openshell command before running it.  Usage: demo/ask.sh "question"
set -euo pipefail
question="${1:-Is order 1042 eligible for a refund?}"
image="${DEMO_AGENT_IMAGE:-openshell-demo-claude:2.1.284}"
prompt="You are Acme's refund assistant. Today is $(date +%Y-%m-%d). Refund policy: unopened items can be refunded within 30 days of delivery.
Look orders up with: curl -s -H \"Authorization: Bearer \$ORDERS_API_KEY\" http://host.openshell.internal:18099/v1/orders/<order id>
Question: $question
Answer in at most two sentences."
cmd=(openshell sandbox create --name refund-agent --from "$image"
     --provider claude --provider acme-orders --no-auto-providers --no-keep --no-tty
     --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 --env DISABLE_AUTOUPDATER=1
     -- bash -c 'claude -p "$1" --allowedTools "Bash(curl:*)" < /dev/null' _ "$prompt")
printf '\033[2m$ openshell sandbox create --name refund-agent --from %s \\\n    --provider claude --provider acme-orders ... -- claude -p "<refund question>"\033[0m\n' "$image"
"${cmd[@]}" 2>&1 | grep -v -E '^\s*\[[0-9.]+s\]|^Created sandbox|deletion accepted|^\s*$' || true
