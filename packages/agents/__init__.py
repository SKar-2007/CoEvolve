"""Agent implementations: Attacker, Developer, Distiller, RegressionGuard."""

__version__ = "0.1.0"

from .training_loop import EpisodeConfig, EpisodeTrace, TrainingLoop

__all__ = ["EpisodeConfig", "EpisodeTrace", "TrainingLoop"]
