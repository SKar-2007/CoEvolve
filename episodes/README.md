# Episodes

Training episode storage and management.

## Structure

```
episodes/
  {episode-id}/
    config.json       # Episode configuration
    trace.json        # Execution trace
    stop/             # Stop conditions and termination
      condition.json  # Why the episode stopped
      signal.json     # Stop signal details
    artifacts/        # Generated code patches, reports
```

## Episode ID Format

Episode IDs follow the pattern: `ep-{timestamp}-{hash}`

Example: `ep-20260912-a1b2c3d4`

## Stop Conditions

Episodes can stop due to:
- **max_episodes**: Reached maximum episode count
- **timeout**: Execution time exceeded
- **convergence**: ELO ratings stabilized
- **error**: Unrecoverable error occurred
- **manual**: Manual termination requested
