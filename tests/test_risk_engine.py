from app.schemas.alert import AlertIngest, AlertSeverity, HostInfo, NormalizedAlert, ProcessInfo
from app.schemas.enrichment import AlertEnrichmentReport, IoCEnrichment, ReputationVerdict
from app.schemas.risk import RiskLevel
from app.services.risk_engine import RiskEngine


def test_baseline_low_severity_alert():
    raw_alert = AlertIngest(
        source="sysmon",
        severity=AlertSeverity.LOW,
        rule_id="1",
        title="Benign test event",
        description="Standard low-severity activity",
        host=HostInfo(hostname="WORKSTATION-99"),
    )
    norm = NormalizedAlert(**raw_alert.model_dump())

    assessment = RiskEngine.calculate_risk(norm)
    assert assessment.score == 5
    assert assessment.level == RiskLevel.LOW
    assert len(assessment.reasons) == 1


def test_compound_risk_critical_score():
    alert = NormalizedAlert(
        source="wazuh",
        severity=AlertSeverity.HIGH,  # +25
        rule_id="100001",
        title="Suspicious PowerShell Activity",
        description="Execution on core server",
        host=HostInfo(hostname="WIN-SRV-AD01"),  # +15 (AD Domain Controller)
        process=ProcessInfo(
            command_line="powershell.exe -NonI -W Hidden -Enc SQBFAFgA..."  # +15 (Obfuscation flag)
        ),
        enrichment=AlertEnrichmentReport(
            enrichments=[
                IoCEnrichment(
                    ioc="198.51.100.23",
                    ioc_type="ipv4",
                    verdict=ReputationVerdict.MALICIOUS,  # +30
                    provider="MockTI",
                )
            ]
        ),
    )

    assessment = RiskEngine.calculate_risk(alert)
    # Calculation: 25 (Base) + 30 (TI) + 15 (Process flags) + 15 (Critical Host) = 85
    assert assessment.score == 85
    assert assessment.level == RiskLevel.CRITICAL
    assert len(assessment.reasons) == 4
    assert any("critical infrastructure" in r for r in assessment.reasons)
    assert any("Confirmed malicious IoC" in r for r in assessment.reasons)