"""
SentinelBridge End-to-End Pipeline Demonstration Script.

Simulates the full detection-to-response lifecycle:
Emulation Scenario -> Sysmon Telemetry -> Translation ->
SentinelBridge API -> Normalization -> TI Enrichment ->
MITRE Mapping -> Risk Scoring -> Incident Escalation -> Ticket & Notification.
"""

import asyncio
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


async def run_scenario(name: str, telemetry: dict, service: AlertService, incident_repo: InMemoryIncidentRepository):
    print(f"\n{'='*75}")
    print(f"[*] RUNNING EMULATION: {name}")
    print(f"{'='*75}")
    print(f"[1] Telemetry Received: Event ID {telemetry.get('event_id')} from {telemetry.get('computer_name')}")

    # 1. Translate raw telemetry into AlertIngest
    alert_ingest = SysmonTelemetryTranslator.translate_event(telemetry)
    print(f"[2] Telemetry Translated: Rule '{alert_ingest.rule_id}' | Title: '{alert_ingest.title}'")

    # 2. Ingest through SentinelBridge SOAR pipeline
    saved_alert, promoted = await service.process_and_ingest(alert_ingest)

    print(f"[3] Alert Ingested & Normalized: UUID={saved_alert.alert_id}")
    print(f"    - Extracted IoCs   : IPs={saved_alert.extracted_iocs.ips}, Domains={saved_alert.extracted_iocs.domains}")
    print(f"    - Enriched TI      : Malicious={saved_alert.enrichment.malicious_count}, Suspicious={saved_alert.enrichment.suspicious_count}")
    print(f"    - MITRE ATT&CK     : {[f'{m.technique_id} ({m.technique_name})' for m in saved_alert.mitre.mappings]}")
    print(f"    - Risk Score       : {saved_alert.risk.score}/100 ({saved_alert.risk.level.value.upper()})")
    print(f"    - Risk Reasons     : {'; '.join(saved_alert.risk.reasons[:2])}...")
    print(f"[4] Escalation Decision: Incident Promoted = {promoted}")

    if promoted:
        incident = await incident_repo.get_by_alert_id(saved_alert.alert_id)
        if incident:
            print(f"[5] Incident Stored    : UUID={incident.incident_id} | Status={incident.status.value}")
            print(f"    - Ticket ID        : {incident.ticket_id}")
            print(f"    - Timeline Entries : {len(incident.timeline)}")


async def main():
    print("\n" + "#"*75)
    print("  SENTINELBRIDGE: MINI-SOAR & DETECTION ENGINEERING DEMONSTRATION")
    print("#"*75)

    # Wire up the modular architecture
    alert_repo = InMemoryAlertRepository()
    incident_repo = InMemoryIncidentRepository()
    ti_provider = MockThreatIntelProvider()
    enrichment_service = EnrichmentService(provider=ti_provider)
    ticketing_provider = LocalTicketProvider()
    notification_provider = ConsoleNotificationProvider()

    incident_service = IncidentService(
        incident_repo=incident_repo,
        ticketing_provider=ticketing_provider,
        notification_provider=notification_provider,
        auto_escalate_threshold=70,
    )

    alert_service = AlertService(
        repository=alert_repo,
        enrichment_service=enrichment_service,
        incident_service=incident_service,
    )

    # Run three distinct atomic attack emulations
    scenarios = [
        AtomicEmulations.emulate_powershell_encoded_command(),
        AtomicEmulations.emulate_schtasks_persistence(),
        AtomicEmulations.emulate_lsass_credential_access(),
    ]

    for scenario in scenarios:
        await run_scenario(scenario["name"], scenario["telemetry"], alert_service, incident_repo)

    print("\n" + "#"*75)
    print("  DEMONSTRATION COMPLETED: ALL EMULATION CHAINS PROCESSED CLEANLY")
    print("#"*75 + "\n")


if __name__ == "__main__":
    asyncio.run(main())