import json
from pathlib import Path
import pytest
from app.detection.translator import SysmonTelemetryTranslator
from app.schemas.alert import AlertSeverity
from app.services.alert_service import AlertService
from app.storage.incident_memory import InMemoryIncidentRepository
from app.storage.memory import InMemoryAlertRepository


def test_translate_powershell_process_creation():
    payload_path = Path("sample_alerts/sysmon_eid1_powershell.json")
    with open(payload_path, "r") as f:
        event = json.load(f)

    alert = SysmonTelemetryTranslator.translate_event(event)

    assert alert.source == "sysmon"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.rule_id == "SIGMA-T1059.001"
    assert alert.host.hostname == "WIN-SRV-AD01"
    assert "obfuscation" in alert.description.lower()
    assert alert.process is not None
    assert "-Enc" in alert.process.command_line


def test_translate_lsass_process_access():
    payload_path = Path("sample_alerts/sysmon_eid10_lsass.json")
    with open(payload_path, "r") as f:
        event = json.load(f)

    alert = SysmonTelemetryTranslator.translate_event(event)

    assert alert.source == "sysmon"
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.rule_id == "SIGMA-T1003.001"
    assert "LSASS Memory Handle" in alert.title


@pytest.mark.asyncio
async def test_end_to_end_sysmon_to_incident_escalation():
    """
    Verifies the complete flow:
    Sysmon EID 10 Event -> Translator -> AlertService Ingestion ->
    IoC Extractor -> TI Enrichment -> Risk Engine -> MITRE Mapping -> Incident Creation
    """
    from app.enrichment.mock import MockThreatIntelProvider
    from app.services.enrichment_service import EnrichmentService
    from app.services.incident_service import IncidentService

    # Setup real pipeline services with in-memory stores
    alert_repo = InMemoryAlertRepository()
    incident_repo = InMemoryIncidentRepository()

    ti_provider = MockThreatIntelProvider()
    enrichment_service = EnrichmentService(provider=ti_provider)
    incident_service = IncidentService(incident_repo=incident_repo, auto_escalate_threshold=70)

    service = AlertService(
        repository=alert_repo,
        enrichment_service=enrichment_service,
        incident_service=incident_service,
    )

    payload_path = Path("sample_alerts/sysmon_eid10_lsass.json")
    with open(payload_path, "r") as f:
        event = json.load(f)

    # 1. Translate
    alert_ingest = SysmonTelemetryTranslator.translate_event(event)

    # 2. Ingest & Process
    saved_alert, promoted = await service.process_and_ingest(alert_ingest)

    # Assert alert properties
    assert saved_alert.risk.score >= 70
    assert promoted is True
    assert any(m.technique_id == "T1003.001" for m in saved_alert.mitre.mappings)

    # Assert incident record was automatically generated
    incident = await incident_repo.get_by_alert_id(saved_alert.alert_id)
    assert incident is not None
    assert incident.host.hostname == "WIN-SRV-AD01"
    assert incident.risk.score >= 70