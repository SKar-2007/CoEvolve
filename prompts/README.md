# prompts/ — manual prompt library (superseded)

This directory is the original file-based prompt prototype:

- `current/` — base system prompts per agent (attacker, developer, distiller, judge)
- `history/` — manual snapshots (`v*.md`)
- `diff/` — offline scripts to diff snapshots and save new versions

**No application code reads these files.** The canonical runtime path is:

- `packages/evolution/store.py` (`PromptStore`, git-backed `.prompt_store/`)
- `GET /prompts/current`, `/prompts/history`, `/prompts/diff/{v1}/{v2}` (`packages/api/main.py`)

The `diff/` scripts remain useful for offline inspection of snapshots, but new
prompt evolution must go through `PromptStore` so the API, Elo tracking, and
distillation loop stay consistent. Do not add new consumers of these files.
