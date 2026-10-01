import pytest
from app.connectors.ticketing.local import LocalTicketProvider
from app.connectors.ticketing.thehive_mock import TheHiveMockConnector
from app.schemas.alert import AlertSeverity, HostInfo, NormalizedAlert
from app.schemas.ioc import ExtractedIoCSet
from app.schemas.mitre import AlertMitreReport, MitreMapping, MitreTactic
from app.schemas.risk import RiskAssessment, RiskLevel
from app.schemas.ticketing import TicketPriority
from app.services.incident_service import IncidentService
from app.storage.incident_memory import InMemoryIncidentRepository


@pytest.mark.asyncio
async def test_local_ticketing_payload_and_artifacts():
    provider = LocalTicketProvider()
    repo = InMemoryIncidentRepository()
    service = IncidentService(incident_repo=repo, ticketing_provider=provider)

    alert = NormalizedAlert(
        source="wazuh",
        severity=AlertSeverity.HIGH,
        rule_id="100001",
        title="CobaltStrike Beacon Outbound",
        description="Encrypted traffic to unauthorized external IP",
        host=HostInfo(hostname="WIN-SRV-AD01"),
        risk=RiskAssessment(score=85, level=RiskLevel.CRITICAL),
        extracted_iocs=ExtractedIoCSet(
            ips=["198.51.100.23"],
            domains=["malicious-c2.internal"],
        ),
        mitre=AlertMitreReport(
            mappings=[
                MitreMapping(
                    technique_id="T1071.001",
                    technique_name="Web Protocols",
                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                    confidence=0.9,
                    evidence="HTTP/S beaconing",
                )
            ]
        ),
    )

    incident = await service.evaluate_and_promote(alert)
    assert incident is not None
    assert incident.ticket_id is not None

    # Retrieve generated ticket
    ticket = await provider.get_ticket(incident.ticket_id)
    assert ticket is not None
    assert ticket.payload.priority == TicketPriority.HIGH
    assert any("mitre:T1071.001" in tag for tag in ticket.payload.tags)
    assert len(ticket.payload.artifacts) == 2  # 1 IP + 1 Domain
    assert any("TICKET_DISPATCHED" in entry.action for entry in incident.timeline)


@pytest.mark.asyncio
async def test_thehive_mock_connector_mapping():
    provider = TheHiveMockConnector(api_endpoint="http://soc-hive.internal:9000")
    repo = InMemoryIncidentRepository()
    service = IncidentService(incident_repo=repo, ticketing_provider=provider)

    alert = NormalizedAlert(
        source="sysmon",
        severity=AlertSeverity.CRITICAL,
        rule_id="10",
        title="LSASS Dumping Detected",
        description="Mimikatz accessed LSASS memory space",
        host=HostInfo(hostname="DC01"),
        risk=RiskAssessment(score=95, level=RiskLevel.CRITICAL),
    )

    incident = await service.evaluate_and_promote(alert)
    assert incident is not None
    assert incident.ticket_id.startswith("THEHIVE-")

    hive_case = await provider.get_ticket(incident.ticket_id)
    assert hive_case is not None
    assert hive_case.payload.severity == "4"  # CRITICAL mapped to Hive Severity 4
    assert "DC01" in hive_case.payload.description