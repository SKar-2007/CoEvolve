# CoEvolve Configuration

Central configuration for the CoEvolve security training platform.

## Structure

```
config/
  settings.yml        # Main application settings
  agents.yml          # Agent configuration
  training.yml        # Training loop parameters
  telemetry.yml       # Monitoring and alerting config
```

## Usage

Configuration is loaded via environment variables or config files:

```python
from config import load_config
config = load_config("settings")
```

## Environment Variables

Override any config value with environment variables:

```bash
COEVOLVE_LOG_LEVEL=debug
COEVOLVE_API_HOST=0.0.0.0
```
