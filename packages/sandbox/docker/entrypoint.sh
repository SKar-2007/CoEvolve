#!/bin/sh
set -e
echo "[sandbox-entrypoint] episode=$COEVOLVE_EPISODE_ID prompt_version=$COEVOLVE_PROMPT_VERSION"
exec "$@"