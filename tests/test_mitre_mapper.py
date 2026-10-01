from app.schemas.alert import AlertIngest, AlertSeverity, HostInfo, NormalizedAlert, ProcessInfo
from app.schemas.ioc import ExtractedIoCSet
from app.schemas.mitre import MitreTactic
from app.services.mitre_mapper import MitreMapper


def test_powershell_and_obfuscation_mapping():
    alert = NormalizedAlert(
        source="wazuh",
        severity=AlertSeverity.HIGH,
        rule_id="100001",
        title="Suspicious PowerShell Encoded Execution",
        description="PowerShell executed with hidden encoded parameters",
        host=HostInfo(hostname="WIN-CL01"),
        process=ProcessInfo(
            command_line="powershell.exe -NoP -W Hidden -Enc SQBFAFgA..."
        ),
    )

    report = MitreMapper.map_alert(alert)
    tech_ids = [m.technique_id for m in report.mappings]

    assert "T1059.001" in tech_ids  # PowerShell
    assert "T1027" in tech_ids      # Obfuscated Files or Information

    ps_mapping = next(m for m in report.mappings if m.technique_id == "T1059.001")
    assert ps_mapping.tactic == MitreTactic.EXECUTION
    assert ps_mapping.confidence >= 0.90
    assert "powershell" in ps_mapping.evidence.lower()


def test_credential_access_mapping():
    alert = NormalizedAlert(
        source="sysmon",
        severity=AlertSeverity.CRITICAL,
        rule_id="10",
        title="Process Access to LSASS",
        description="Suspicious handle created to lsass.exe for credential dumping",
        host=HostInfo(hostname="WIN-SRV01"),
    )

    report = MitreMapper.map_alert(alert)
    tech_ids = [m.technique_id for m in report.mappings]

    assert "T1003.001" in tech_ids
    lsass_mapping = next(m for m in report.mappings if m.technique_id == "T1003.001")
    assert lsass_mapping.tactic == MitreTactic.CREDENTIAL_ACCESS


def test_c2_url_mapping():
    alert = NormalizedAlert(
        source="suricata",
        severity=AlertSeverity.HIGH,
        rule_id="2001",
        title="Outbound C2 Connection",
        description="Observed beaconing traffic",
        host=HostInfo(hostname="WIN-CL02"),
        extracted_iocs=ExtractedIoCSet(
            urls=["http://malicious-c2.internal/beacon"]
        ),
    )

    report = MitreMapper.map_alert(alert)
    tech_ids = [m.technique_id for m in report.mappings]

    assert "T1071.001" in tech_ids
    c2_mapping = next(m for m in report.mappings if m.technique_id == "T1071.001")
    assert c2_mapping.tactic == MitreTactic.COMMAND_AND_CONTROL