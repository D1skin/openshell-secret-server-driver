# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
# Sandbox image for the demo: Claude Code plus curl, running as a non-root user whose
# home is the sandbox working directory (writable under OpenShell's default policy).
FROM node:22-bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ARG CLAUDE_CODE_VERSION=2.1.284
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" && npm cache clean --force
RUN groupadd --gid 1500 agent \
    && useradd --uid 1500 --gid agent --home-dir /sandbox --create-home agent
WORKDIR /sandbox
USER agent
