"""Tests for alert channels and manager (HTTP/SMTP stubbed)."""

from __future__ import annotations

from packages.telemetry.alerting import (
    Alert,
    AlertManager,
    EmailChannel,
    LogChannel,
    PagerDutyChannel,
    SlackChannel,
)


def _alert(**kwargs):
    return Alert(title="t", message="m", **kwargs)


class _Resp:
    def raise_for_status(self):
        return None


class TestSlack:
    def test_success(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            "httpx.post",
            lambda url, json=None, timeout=None: (seen.update(json=json), _Resp())[1],
        )
        assert SlackChannel("http://hook").send(_alert(severity="error")) is True
        assert seen["json"]["attachments"][0]["color"] == "#ff0000"

    def test_failure_returns_false(self, monkeypatch):
        def boom(url, json=None, timeout=None):
            raise ConnectionError("down")

        monkeypatch.setattr("httpx.post", boom)
        assert SlackChannel("http://hook").send(_alert()) is False


class TestPagerDuty:
    def test_severity_mapping(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            "httpx.post",
            lambda url, json=None, timeout=None: (seen.update(json=json), _Resp())[1],
        )
        assert PagerDutyChannel("key").send(_alert(severity="critical")) is True
        assert seen["json"]["payload"]["severity"] == "critical"
        assert seen["json"]["event_action"] == "trigger"

    def test_failure_returns_false(self, monkeypatch):
        monkeypatch.setattr(
            "httpx.post",
            lambda *a, **k: (_ for _ in ()).throw(TimeoutError("t")),
        )
        assert PagerDutyChannel("key").send(_alert()) is False


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sent = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        return None

    def login(self, user, password):
        self.user = user
        return None

    def sendmail(self, frm, to, msg):
        self.sent.append((frm, to, msg))
        return {}


class TestEmail:
    def test_no_recipients(self):
        assert EmailChannel("smtp.x", to_addrs=[]).send(_alert()) is False

    def test_success(self, monkeypatch):
        FakeSMTP.instances.clear()
        monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
        ch = EmailChannel("smtp.x", username="u", password="p", from_addr="a@x", to_addrs=["b@x"])
        assert ch.send(_alert(metadata={"k": "v"})) is True
        assert len(FakeSMTP.instances[0].sent) == 1

    def test_failure_returns_false(self, monkeypatch):
        class Broken(FakeSMTP):
            def sendmail(self, frm, to, msg):
                raise OSError("smtp down")

        monkeypatch.setattr("smtplib.SMTP", Broken)
        ch = EmailChannel("smtp.x", from_addr="a@x", to_addrs=["b@x"])
        assert ch.send(_alert()) is False


class TestManager:
    def test_fallback_log_channel(self):
        results = AlertManager().send(_alert())
        assert results == {"LogChannel": True}

    def test_per_channel_results(self):
        class Ok:
            def send(self, alert):
                return True

        class Bad:
            def send(self, alert):
                return False

        m = AlertManager()
        m.add_channel(Ok())
        m.add_channel(Bad())
        assert m.send(_alert()) == {"Ok": True, "Bad": False}

    def test_convenience_methods(self):
        m = AlertManager()
        assert m.notify_training_complete("ep1", 1, 2.5, 1500.0, 1500.0)["LogChannel"] is True
        assert m.notify_rule_distilled("rule", "SQLi")["LogChannel"] is True
        assert m.notify_error("boom", context="ctx")["LogChannel"] is True

    def test_log_channel_always_true(self):
        assert LogChannel().send(_alert(severity="critical")) is True
        assert LogChannel().send(_alert(severity="weird")) is True
