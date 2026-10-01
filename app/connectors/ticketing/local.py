from uuid import uuid4
from app.connectors.ticketing.base import TicketingProvider
from app.schemas.alert import AlertSeverity
from app.schemas.incident import Incident
from app.schemas.ticketing import TicketPayload, TicketPriority, TicketRecord


class LocalTicketProvider(TicketingProvider):
    """Deterministic in-memory ticketing provider for development and testing."""

    SEVERITY_TO_PRIORITY = {
        AlertSeverity.CRITICAL: TicketPriority.CRITICAL,
        AlertSeverity.HIGH: TicketPriority.HIGH,
        AlertSeverity.MEDIUM: TicketPriority.MEDIUM,
        AlertSeverity.LOW: TicketPriority.LOW,
    }

    def __init__(self) -> None:
        self._tickets: dict[str, TicketRecord] = {}

    @property
    def provider_name(self) -> str:
        return "LocalTicketProvider"

    async def create_ticket(self, incident: Incident) -> TicketRecord:
        priority = self.SEVERITY_TO_PRIORITY.get(incident.severity, TicketPriority.MEDIUM)

        # Build observable artifacts
        artifacts = []
        for ip in incident.extracted_iocs.ips:
            artifacts.append({"data_type": "ip", "value": ip})
        for domain in incident.extracted_iocs.domains:
            artifacts.append({"data_type": "domain", "value": domain})
        for h in incident.extracted_iocs.sha256:
            artifacts.append({"data_type": "hash", "value": h})

        # Build tags including MITRE techniques
        tags = [f"severity:{incident.severity.value}", f"risk_score:{incident.risk.score}"]
        for m in incident.mitre.mappings:
            tags.append(f"mitre:{m.technique_id}")

        ticket_id = f"TICK-{uuid4().hex[:8].upper()}"

        payload = TicketPayload(
            title=f"[{priority.value}] {incident.title}",
            description=(
                f"Incident Escalated: {incident.title}\n"
                f"Risk Score: {incident.risk.score}/100\n"
                f"Affected Host: {incident.host.hostname}\n"
                f"Reasons: {', '.join(incident.risk.reasons)}"
            ),
            severity=incident.severity.value,
            priority=priority,
            tags=tags,
            source_incident_id=incident.incident_id,
            artifacts=artifacts,
        )

        record = TicketRecord(
            ticket_id=ticket_id,
            provider=self.provider_name,
            external_url=f"http://sentinelbridge.local/tickets/{ticket_id}",
            payload=payload,
        )

        self._tickets[ticket_id] = record
        return record

    async def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        return self._tickets.get(ticket_id)

    def clear(self) -> None:
        self._tickets.clear()