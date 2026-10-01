import pytest
from app.connectors.ticketing.local import LocalTicketProvider
from app.detection.translator import SysmonTelemetryTranslator
from app.enrichment.mock import MockThreatIntelProvider
from app.notifications.console import ConsoleNotificationProvider
from app.services.alert_service import AlertService
from app.services.enrichment_service import EnrichmentService
from app.services.incident_service import IncidentService
from app.storage.incident_memory import InMemoryIncidentRepository
from app.storage.memory import InMemoryAlertRepository
from emulation.atomic_tests import AtomicEmulations


@pytest.mark.asyncio
async def test_full_pipeline_atomic_powershell():
    alert_repo = InMemoryAlertRepository()
    incident_repo = InMemoryIncidentRepository()
    service = AlertService(
        repository=alert_repo,
        enrichment_service=EnrichmentService(MockThreatIntelProvider()),
        incident_service=IncidentService(incident_repo, LocalTicketProvider(), ConsoleNotificationProvider()),
    )

    scenario = AtomicEmulations.emulate_powershell_encoded_command()
    alert_ingest = SysmonTelemetryTranslator.translate_event(scenario["telemetry"])
    saved_alert, promoted = await service.process_and_ingest(alert_ingest)

    assert saved_alert.risk.score >= 50
    assert any(m.technique_id == "T1059.001" for m in saved_alert.mitre.mappings)


@pytest.mark.asyncio
async def test_full_pipeline_atomic_lsass():
    alert_repo = InMemoryAlertRepository()
    incident_repo = InMemoryIncidentRepository()
    service = AlertService(
        repository=alert_repo,
        enrichment_service=EnrichmentService(MockThreatIntelProvider()),
        incident_service=IncidentService(incident_repo, LocalTicketProvider(), ConsoleNotificationProvider(), auto_escalate_threshold=70),
    )

    scenario = AtomicEmulations.emulate_lsass_credential_access()
    alert_ingest = SysmonTelemetryTranslator.translate_event(scenario["telemetry"])
    saved_alert, promoted = await service.process_and_ingest(alert_ingest)

    assert saved_alert.risk.score >= 80
    assert promoted is True

    incident = await incident_repo.get_by_alert_id(saved_alert.alert_id)
    assert incident is not None
    assert incident.ticket_id is not None