import re
from app.schemas.alert import AlertSeverity, NormalizedAlert
from app.schemas.enrichment import ReputationVerdict
from app.schemas.mitre import MitreTactic
from app.schemas.risk import RiskAssessment, RiskFactor, RiskLevel


class RiskEngine:
    SEVERITY_WEIGHTS = {
        AlertSeverity.CRITICAL: 40,
        AlertSeverity.HIGH: 25,
        AlertSeverity.MEDIUM: 15,
        AlertSeverity.LOW: 5,
    }

    CRITICAL_ASSET_PATTERN = re.compile(
        r"(?:-|\b)(?:dc|ad|srv-ad|db|core|kdc|pki)(?:-|\b|\d)",
        re.IGNORECASE,
    )

    SUSPICIOUS_EXEC_PATTERNS = re.compile(
        r"(?:-enc|-encodedcommand|bypass|iex|invoke-expression|downloadstring|wscript\.shell)",
        re.IGNORECASE,
    )

    # High-impact tactics/techniques that directly elevate threat tier
    HIGH_RISK_TACTICS = {
        MitreTactic.CREDENTIAL_ACCESS: 25,
        MitreTactic.IMPACT: 25,
        MitreTactic.COMMAND_AND_CONTROL: 20,
        MitreTactic.LATERAL_MOVEMENT: 20,
    }

    @classmethod
    def calculate_risk(cls, alert: NormalizedAlert) -> RiskAssessment:
        factors: list[RiskFactor] = []
        raw_score = 0

        # 1. Base Severity Weight
        base_delta = cls.SEVERITY_WEIGHTS.get(alert.severity, 5)
        raw_score += base_delta
        factors.append(
            RiskFactor(
                rule="BASE_SEVERITY",
                delta=base_delta,
                description=f"Base alert severity: {alert.severity.value.upper()}",
            )
        )

        # 2. MITRE ATT&CK Tactical Weight
        mitre_delta = 0
        observed_tactics = set()
        for mapping in alert.mitre.mappings:
            if mapping.tactic in cls.HIGH_RISK_TACTICS and mapping.tactic not in observed_tactics:
                delta = cls.HIGH_RISK_TACTICS[mapping.tactic]
                mitre_delta += delta
                observed_tactics.add(mapping.tactic)
                factors.append(
                    RiskFactor(
                        rule=f"MITRE_{mapping.tactic.name}",
                        delta=delta,
                        description=f"High-impact ATT&CK technique confirmed: {mapping.technique_id} ({mapping.technique_name})",
                    )
                )
        # Cap MITRE tactical contribution to 35 points max
        raw_score += min(mitre_delta, 35)

        # 3. Enriched Threat Intelligence Verdicts
        ti_delta = 0
        for enrichment in alert.enrichment.enrichments:
            if enrichment.verdict == ReputationVerdict.MALICIOUS:
                delta = 30
                ti_delta += delta
                factors.append(
                    RiskFactor(
                        rule="THREAT_INTEL_MALICIOUS",
                        delta=delta,
                        description=f"Confirmed malicious IoC ({enrichment.ioc}) via {enrichment.provider}",
                    )
                )
            elif enrichment.verdict == ReputationVerdict.SUSPICIOUS:
                delta = 15
                ti_delta += delta
                factors.append(
                    RiskFactor(
                        rule="THREAT_INTEL_SUSPICIOUS",
                        delta=delta,
                        description=f"Suspicious reputation for IoC ({enrichment.ioc}) via {enrichment.provider}",
                    )
                )

        raw_score += min(ti_delta, 50)

        # 4. Execution Mechanics & CommandLine Evasion
        if alert.process and alert.process.command_line:
            if cls.SUSPICIOUS_EXEC_PATTERNS.search(alert.process.command_line):
                exec_delta = 15
                raw_score += exec_delta
                factors.append(
                    RiskFactor(
                        rule="SUSPICIOUS_EXECUTION_FLAGS",
                        delta=exec_delta,
                        description="Observed execution evasion or obfuscation flags in command line",
                    )
                )

        # 5. Asset Criticality
        if cls.CRITICAL_ASSET_PATTERN.search(alert.host.hostname):
            asset_delta = 15
            raw_score += asset_delta
            factors.append(
                RiskFactor(
                    rule="HIGH_VALUE_ASSET",
                    delta=asset_delta,
                    description=f"Target host designated as critical infrastructure: {alert.host.hostname}",
                )
            )

        final_score = max(0, min(100, raw_score))

        if final_score >= 80:
            level = RiskLevel.CRITICAL
        elif final_score >= 60:
            level = RiskLevel.HIGH
        elif final_score >= 40:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        reasons = [f.description for f in factors]

        return RiskAssessment(
            score=final_score,
            level=level,
            reasons=reasons,
            factors=factors,
        )