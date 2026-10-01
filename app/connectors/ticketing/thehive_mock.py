import logging
from uuid import uuid4
from app.connectors.ticketing.base import TicketingProvider
from app.schemas.alert import AlertSeverity
from app.schemas.incident import Incident
from app.schemas.ticketing import TicketPayload, TicketPriority, TicketRecord

logger = logging.getLogger("sentinelbridge.connectors.thehive")


class TheHiveMockConnector(TicketingProvider):
    """
    Simulates TheHive Case API (v4/v5) payload serialization and error handling.
    Enforces format compatibility without requiring a live external container.
    """

    SEV_MAP = {
        AlertSeverity.LOW: 1,
        AlertSeverity.MEDIUM: 2,
        AlertSeverity.HIGH: 3,
        AlertSeverity.CRITICAL: 4,
    }

    def __init__(self, api_endpoint: str = "http://thehive.lab:9000", api_key: str = "mock-key") -> None:
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self._cases: dict[str, TicketRecord] = {}

    @property
    def provider_name(self) -> str:
        return "TheHiveConnector"

    async def create_ticket(self, incident: Incident) -> TicketRecord:
        # Transformation into TheHive Case Schema
        hive_severity = self.SEV_MAP.get(incident.severity, 2)
        hive_tags = [f"mitre:{m.technique_id}" for m in incident.mitre.mappings]
        hive_tags.append(f"host:{incident.host.hostname}")

        case_id = f"THEHIVE-{uuid4().hex[:6].upper()}"

        payload = TicketPayload(
            title=f"[TheHive Case] {incident.title}",
            description=f"Automated SOC escalation from SentinelBridge. Host: {incident.host.hostname}",
            severity=str(hive_severity),
            priority=TicketPriority.HIGH if hive_severity >= 3 else TicketPriority.MEDIUM,
            tags=hive_tags,
            source_incident_id=incident.incident_id,
            artifacts=[{"type": "ip", "value": ip} for ip in incident.extracted_iocs.ips],
        )

        record = TicketRecord(
            ticket_id=case_id,
            provider=self.provider_name,
            external_url=f"{self.api_endpoint}/index.html#/case/{case_id}/details",
            payload=payload,
        )

        self._cases[case_id] = record
        logger.info(f"Successfully generated case {case_id} via {self.provider_name}")
        return record

    async def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        return self._cases.get(ticket_id)