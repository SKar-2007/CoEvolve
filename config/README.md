# CoEvolve Configuration

Central configuration for the CoEvolve security training platform.

## Runtime configuration (source of truth)

The application loads **all** runtime settings from the environment / `.env`
via `packages/api/config.py` (`pydantic-settings`). See `.env.example` for
the full variable list. There is no `load_config` helper — ignore any docs
suggesting otherwise.

## Reference YAMLs (not loaded)

```
config/
  settings.yml        # Design reference: intended app settings
  agents.yml          # Design reference: agent parameters
  training.yml        # Design reference: training loop parameters
  telemetry.yml       # Design reference: monitoring and alerting
```

These files document the intended configuration schema but **no code reads
them**. Keep them in sync with `packages/api/config.py` / `.env.example`
when adding settings, or delete them once superseded.

## Environment Variables

Key runtime variables (see `.env.example` for all):

```bash
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
REQUIRE_AUTH=true
API_KEY_STORE=db
CORS_ORIGINS=https://app.example.com
```
