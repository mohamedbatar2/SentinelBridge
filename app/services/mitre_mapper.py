import re
from app.schemas.alert import NormalizedAlert
from app.schemas.mitre import AlertMitreReport, MitreMapping, MitreTactic


class MitreMapper:
    """
    Deterministic rule-based mapping engine that links alert telemetry
    to verified MITRE ATT&CK techniques with auditable evidence.
    """

    MAPPING_RULES = [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": MitreTactic.EXECUTION,
            "confidence": 0.95,
            "patterns": [re.compile(r"\bpowershell(?:\.exe)?\b", re.IGNORECASE)],
            "field": "process.command_line",
        },
        {
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task",
            "tactic": MitreTactic.PERSISTENCE,
            "confidence": 0.90,
            "patterns": [
                re.compile(r"\bschtasks(?:\.exe)?\b", re.IGNORECASE),
                re.compile(r"scheduled\s*task", re.IGNORECASE),
            ],
            "field": "process.command_line",
        },
        {
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
            "tactic": MitreTactic.CREDENTIAL_ACCESS,
            "confidence": 0.95,
            "patterns": [
                re.compile(r"\blsass(?:\.exe)?\b", re.IGNORECASE),
                re.compile(r"mimikatz", re.IGNORECASE),
                re.compile(r"procdump.*lsass", re.IGNORECASE),
            ],
            "field": "unstructured_corpus",
        },
        {
            "technique_id": "T1071.001",
            "technique_name": "Web Protocols",
            "tactic": MitreTactic.COMMAND_AND_CONTROL,
            "confidence": 0.85,
            "patterns": [
                re.compile(r"https?://", re.IGNORECASE),
            ],
            "field": "iocs.urls",
        },
        {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": MitreTactic.DEFENSE_EVASION,
            "confidence": 0.90,
            "patterns": [
                re.compile(r"(?:-enc|-encodedcommand)\b", re.IGNORECASE),
            ],
            "field": "process.command_line",
        },
    ]

    @classmethod
    def map_alert(cls, alert: NormalizedAlert) -> AlertMitreReport:
        report = AlertMitreReport()
        matched_techniques = set()

        cmd_line = alert.process.command_line if alert.process else ""
        corpus = f"{alert.title} {alert.description} {cmd_line}".lower()
        has_urls = bool(alert.extracted_iocs.urls)

        for rule in cls.MAPPING_RULES:
            tech_id = rule["technique_id"]
            if tech_id in matched_techniques:
                continue

            target_field = rule["field"]
            matched = False
            evidence_str = ""

            if target_field == "process.command_line" and cmd_line:
                for pattern in rule["patterns"]:
                    match = pattern.search(cmd_line)
                    if match:
                        matched = True
                        evidence_str = f"Pattern '{match.group(0)}' detected in command line: {cmd_line[:80]}"
                        break

            elif target_field == "unstructured_corpus":
                for pattern in rule["patterns"]:
                    match = pattern.search(corpus)
                    if match:
                        matched = True
                        evidence_str = f"Pattern '{match.group(0)}' detected in alert metadata/payload"
                        break

            elif target_field == "iocs.urls" and has_urls:
                matched = True
                evidence_str = f"Observed outbound HTTP/S IoC: {alert.extracted_iocs.urls[0]}"

            if matched:
                report.mappings.append(
                    MitreMapping(
                        technique_id=tech_id,
                        technique_name=rule["technique_name"],
                        tactic=rule["tactic"],
                        confidence=rule["confidence"],
                        evidence=evidence_str,
                    )
                )
                matched_techniques.add(tech_id)

        return report