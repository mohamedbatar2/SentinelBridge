import logging
import httpx
from app.notifications.base import NotificationProvider
from app.schemas.incident import Incident
from app.schemas.notification import NotificationChannel, NotificationDeliveryReceipt, NotificationMessage

logger = logging.getLogger("sentinelbridge.notifications.webhook")


class WebhookNotificationProvider(NotificationProvider):
    """Delivers structured JSON incident notifications to a remote webhook URL."""

    def __init__(self, webhook_url: str, timeout_seconds: float = 5.0) -> None:
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds

    @property
    def channel_name(self) -> str:
        return "webhook"

    async def send_incident_alert(self, incident: Incident) -> NotificationDeliveryReceipt:
        message = NotificationMessage(
            incident_id=incident.incident_id,
            title=incident.title,
            severity=incident.severity.value,
            risk_score=incident.risk.score,
            hostname=incident.host.hostname,
            summary="; ".join(incident.risk.reasons),
            top_iocs=incident.extracted_iocs.ips + incident.extracted_iocs.domains,
            mitre_techniques=[m.technique_id for m in incident.mitre.mappings],
        )

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    self.webhook_url,
                    json=message.model_dump(mode="json"),
                )
                delivered = response.is_success
                return NotificationDeliveryReceipt(
                    channel=NotificationChannel.WEBHOOK,
                    delivered=delivered,
                    status_code=response.status_code,
                    details=f"Remote server responded with HTTP {response.status_code}",
                )
        except Exception as exc:
            logger.warning(f"Failed to deliver incident notification to {self.webhook_url}: {exc}")
            return NotificationDeliveryReceipt(
                channel=NotificationChannel.WEBHOOK,
                delivered=False,
                status_code=None,
                details=str(exc),
            )