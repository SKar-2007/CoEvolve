# Dev/base image for CoEvolve Sandbox evaluation containers.
FROM python:3.11-slim

# --- Non-root user ---
RUN groupadd -r agent && useradd -r -g agent -d /workspace -s /bin/bash agent

# --- Minimal tooling ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Workspace ---
WORKDIR /workspace
RUN chown -R agent:agent /workspace && chown -R agent:agent /tmp

# --- Sandbox health probe wrapper (agent code) ---
COPY packages/sandbox/docker/entrypoint.sh /usr/local/bin/sandbox-entrypoint.sh
RUN chmod +x /usr/local/bin/sandbox-entrypoint.sh

USER agent
ENTRYPOINT ["sandbox-entrypoint.sh"]