'''Prometheus metrics exporters for CoEvolve Sandbox telemetry.'''''

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# Counters
EPISODES_TOTAL = Counter("coevolve_episodes_total", "Total training episodes completed")
RULES_DISTILLED = Counter("coevolve_rules_distilled", "Number of security rules distilled")
VULNERABILITIES_DETECTED = Counter(
    "coevolve_vulnerabilities_detected_total",
    "Total vulnerability detections by class",
    ["vuln_class"],
)

# Gauges
ATTACKER_ELO = Gauge("coevolve_attacker_elo", "Attacker player Elo rating")
DEVELOPER_ELO = Gauge("coevolve_developer_elo", "Developer player Elo rating")
RULES_COUNT = Gauge("coevolve_rules_count", "Current number of distilled rules")
DOCKER_CONTAINERS_RUNNING = Gauge("coevolve_docker_containers_running", "Number of active sandbox containers")

# Histograms
EPISODE_DURATION = Histogram("coevolve_episode_duration_seconds", "Episode execution time")
LLM_LATENCY = Histogram("coevolve_llm_latency_seconds", "LLM call latency", ["provider"])
JUDGE_EVALUATION_TIME = Histogram("coevolve_judge_evaluation_seconds", "Hybrid judge execution time")

# Function to update metrics from an episode result
def record_episode(outcome: int, vuln_class: str | None = None, duration_s: float = 0) -> None:
    EPISODES_TOTAL.inc()
    EPISODE_DURATION.observe(duration_s)
    if outcome == 1 and vuln_class:
        VULNERABILITIES_DETECTED.labels(vuln_class=vuln_class).inc()

def update_elo(attacker: float, developer: float) -> None:
    ATTACKER_ELO.set(attacker)
    DEVELOPER_ELO.set(developer)

def set_rule_count(count: int) -> None:
    RULES_COUNT.set(count)
