"""Unit tests for Prometheus telemetry metrics."""

from __future__ import annotations

from packages.telemetry.exporters.metrics import (
    EPISODES_TOTAL,
    ATTACKER_ELO,
    DEVELOPER_ELO,
    RULES_COUNT,
    record_episode,
    set_rule_count,
    update_elo,
)


class TestMetrics:
    def test_record_episode(self) -> None:
        before = EPISODES_TOTAL._value.get()
        record_episode(outcome=0, vuln_class="SQLi", duration_s=1.5)
        after = EPISODES_TOTAL._value.get()
        assert after == before + 1

    def test_update_elo(self) -> None:
        update_elo(1600.0, 1400.0)
        assert ATTACKER_ELO._value.get() == 1600.0
        assert DEVELOPER_ELO._value.get() == 1400.0

    def test_set_rule_count(self) -> None:
        set_rule_count(42)
        assert RULES_COUNT._value.get() == 42

    def test_record_vulnerability(self) -> None:
        from packages.telemetry.exporters.metrics import VULNERABILITIES_DETECTED

        record_episode(outcome=1, vuln_class="XSS", duration_s=2.0)
        # Counter should have incremented
        assert VULNERABILITIES_DETECTED.labels(vuln_class="XSS")._value.get() >= 1
