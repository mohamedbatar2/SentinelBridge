import logging
from app.notifications.base import NotificationProvider
from app.schemas.incident import Incident
from app.schemas.notification import NotificationChannel, NotificationDeliveryReceipt

logger = logging.getLogger("sentinelbridge.notifications.console")


class ConsoleNotificationProvider(NotificationProvider):
    """Prints formatted SOC incident cards to stdout / logging stream."""

    @property
    def channel_name(self) -> str:
        return "console"

    async def send_incident_alert(self, incident: Incident) -> NotificationDeliveryReceipt:
        tech_list = ", ".join([f"{m.technique_id} ({m.technique_name})" for m in incident.mitre.mappings]) or "None"
        ioc_list = ", ".join(incident.extracted_iocs.ips + incident.extracted_iocs.domains) or "None"

        card = (
            f"\n{'='*70}\n"
            f"[SENTINELBRIDGE SOAR ALERT] INCIDENT ESCALATED\n"
            f"{'='*70}\n"
            f"Incident ID : {incident.incident_id}\n"
            f"Title       : {incident.title}\n"
            f"Severity    : {incident.severity.value.upper()} (Risk Score: {incident.risk.score}/100)\n"
            f"Host        : {incident.host.hostname}\n"
            f"MITRE ATT&CK: {tech_list}\n"
            f"IoCs        : {ioc_list}\n"
            f"Reasons     : {'; '.join(incident.risk.reasons)}\n"
            f"{'='*70}\n"
        )
        print(card)
        logger.info(f"Dispatched incident notification to console for {incident.incident_id}")

        return NotificationDeliveryReceipt(
            channel=NotificationChannel.CONSOLE,
            delivered=True,
            status_code=200,
            details="Printed to stdout",
        )