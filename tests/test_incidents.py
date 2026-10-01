import pytest
from app.schemas.alert import AlertIngest, AlertSeverity, HostInfo, NormalizedAlert, ProcessInfo
from app.schemas.incident import IncidentStatus
from app.schemas.risk import RiskAssessment, RiskLevel
from app.services.incident_service import IncidentService, IncidentStateError
from app.storage.incident_memory import InMemoryIncidentRepository


@pytest.mark.asyncio
async def test_low_risk_alert_does_not_escalate():
    repo = InMemoryIncidentRepository()
    service = IncidentService(incident_repo=repo, auto_escalate_threshold=70)

    alert = NormalizedAlert(
        source="sysmon",
        severity=AlertSeverity.LOW,
        rule_id="1",
        title="Routine Process Execution",
        description="powershell.exe executed by developer",
        host=HostInfo(hostname="DEV-LAPTOP"),
        risk=RiskAssessment(score=20, level=RiskLevel.LOW),
    )

    incident = await service.evaluate_and_promote(alert)
    assert incident is None
    assert len(await repo.list_all()) == 0


@pytest.mark.asyncio
async def test_high_risk_alert_promotes_to_incident():
    repo = InMemoryIncidentRepository()
    service = IncidentService(incident_repo=repo, auto_escalate_threshold=70)

    alert = NormalizedAlert(
        source="wazuh",
        severity=AlertSeverity.HIGH,
        rule_id="100001",
        title="Obfuscated C2 Beacon Execution",
        description="PowerShell execution contacting external IP",
        host=HostInfo(hostname="WIN-SRV-AD01"),
        risk=RiskAssessment(score=85, level=RiskLevel.CRITICAL),
    )

    incident = await service.evaluate_and_promote(alert)
    assert incident is not None
    assert incident.status == IncidentStatus.NEW
    assert incident.alert_id == alert.alert_id
    assert len(incident.timeline) == 1
    assert "INCIDENT_CREATED" in incident.timeline[0].action


@pytest.mark.asyncio
async def test_state_machine_valid_and_invalid_transitions():
    repo = InMemoryIncidentRepository()
    service = IncidentService(incident_repo=repo)

    alert = NormalizedAlert(
        source="wazuh",
        severity=AlertSeverity.CRITICAL,
        rule_id="999",
        title="Ransomware Canary Triggered",
        description="Mass file encryption observed",
        host=HostInfo(hostname="FS01"),
        risk=RiskAssessment(score=95, level=RiskLevel.CRITICAL),
    )
    incident = await service.evaluate_and_promote(alert)
    assert incident is not None

    # Valid step 1: NEW -> TRIAGED
    triaged = await service.transition_status(
        incident.incident_id,
        new_status=IncidentStatus.TRIAGED,
        actor="soc_analyst_1",
        notes="Alert confirmed real; initial triage started",
    )
    assert triaged.status == IncidentStatus.TRIAGED

    # Invalid step: Cannot jump directly from TRIAGED -> RESOLVED (must investigate & contain first)
    with pytest.raises(IncidentStateError):
        await service.transition_status(
            incident.incident_id,
            new_status=IncidentStatus.RESOLVED,
            actor="soc_analyst_1",
            notes="Attempting illegal skip",
        )

    # Valid step 2: TRIAGED -> INVESTIGATING
    investigating = await service.transition_status(
        incident.incident_id,
        new_status=IncidentStatus.INVESTIGATING,
        actor="soc_analyst_1",
    )
    assert investigating.status == IncidentStatus.INVESTIGATING