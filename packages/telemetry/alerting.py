"""Alert notification system for CoEvolve Sandbox.

Supports Slack webhooks, email (SMTP), and PagerDuty.
Falls back to logging if no alerting backend is configured.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """An alert to send via configured channels."""

    title: str
    message: str
    severity: str = "info"  # info, warning, error, critical
    source: str = "coevolve"
    metadata: dict[str, Any] = field(default_factory=dict)


class AlertChannel(ABC):
    """Base class for alert notification channels."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True if successful."""


class SlackChannel(AlertChannel):
    """Send alerts via Slack incoming webhook."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> bool:
        import httpx

        color = {
            "info": "#36a64f",
            "warning": "#ff9900",
            "error": "#ff0000",
            "critical": "#990000",
        }.get(alert.severity, "#36a64f")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"[{alert.severity.upper()}] {alert.title}",
                    "text": alert.message,
                    "footer": alert.source,
                    "fields": [
                        {"title": k, "value": str(v), "short": True}
                        for k, v in alert.metadata.items()
                    ],
                }
            ]
        }
        try:
            resp = httpx.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("Slack alert failed: %s", exc)
            return False


class EmailChannel(AlertChannel):
    """Send alerts via SMTP email."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        from_addr: str = "",
        to_addrs: list[str] | None = None,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs or []

    def send(self, alert: Alert) -> bool:
        if not self.to_addrs:
            logger.warning("No email recipients configured")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[CoEvolve {alert.severity.upper()}] {alert.title}"
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        body = f"{alert.message}\n\nSource: {alert.source}"
        if alert.metadata:
            body += "\n\nDetails:\n" + "\n".join(f"  {k}: {v}" for k, v in alert.metadata.items())

        msg.attach(MIMEText(body, "plain"))

        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls(context=context)
                if self.username:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            return True
        except Exception as exc:
            logger.warning("Email alert failed: %s", exc)
            return False


class PagerDutyChannel(AlertChannel):
    """Send alerts via PagerDuty Events API v2."""

    def __init__(self, routing_key: str) -> None:
        self.routing_key = routing_key

    def send(self, alert: Alert) -> bool:
        import httpx

        severity_map = {
            "info": "info",
            "warning": "warning",
            "error": "error",
            "critical": "critical",
        }
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"{alert.title}: {alert.message}",
                "source": alert.source,
                "severity": severity_map.get(alert.severity, "info"),
                "custom_details": alert.metadata,
            },
        }
        try:
            resp = httpx.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("PagerDuty alert failed: %s", exc)
            return False


class LogChannel(AlertChannel):
    """Fallback: log alerts via Python logging."""

    def send(self, alert: Alert) -> bool:
        log_fn = {
            "info": logger.info,
            "warning": logger.warning,
            "error": logger.error,
            "critical": logger.critical,
        }.get(alert.severity, logger.info)
        log_fn("[%s] %s: %s", alert.source.upper(), alert.title, alert.message)
        return True


class AlertManager:
    """Manages multiple alert channels and dispatches alerts."""

    def __init__(self) -> None:
        self._channels: list[AlertChannel] = []

    def add_channel(self, channel: AlertChannel) -> None:
        self._channels.append(channel)

    def send(self, alert: Alert) -> dict[str, bool]:
        """Send alert to all configured channels. Returns per-channel status."""
        if not self._channels:
            # Auto-add log channel as fallback
            self._channels.append(LogChannel())

        results: dict[str, bool] = {}
        for channel in self._channels:
            name = type(channel).__name__
            results[name] = channel.send(alert)
        return results

    def notify_training_complete(
        self,
        episode_id: str,
        outcome: int,
        duration_s: float,
        attacker_elo: float,
        developer_elo: float,
    ) -> dict[str, bool]:
        """Convenience: send a training episode complete notification."""
        severity = "warning" if outcome == 1 else "info"
        return self.send(Alert(
            title=f"Episode {episode_id} Complete",
            message=f"{'VULNERABILITY FOUND' if outcome else 'Secure'} in {duration_s:.1f}s",
            severity=severity,
            metadata={
                "episode_id": episode_id,
                "attacker_elo": f"{attacker_elo:.0f}",
                "developer_elo": f"{developer_elo:.0f}",
            },
        ))

    def notify_rule_distilled(self, rule_text: str, vuln_class: str) -> dict[str, bool]:
        """Convenience: send a rule distilled notification."""
        return self.send(Alert(
            title="New Security Rule Distilled",
            message=rule_text,
            severity="info",
            metadata={"vulnerability_class": vuln_class},
        ))

    def notify_error(self, error: str, context: str = "") -> dict[str, bool]:
        """Convenience: send an error notification."""
        return self.send(Alert(
            title="System Error",
            message=error,
            severity="error",
            metadata={"context": context} if context else {},
        ))
