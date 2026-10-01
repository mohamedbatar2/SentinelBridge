from datetime import datetime, timezone
from typing import Any
from app.schemas.alert import AlertIngest, AlertSeverity, HostInfo, ProcessInfo, RawIoCs


class SysmonTelemetryTranslator:
    """
    Translates raw Sysmon Windows Event telemetry (Event ID 1, 10, etc.)
    into validated, standardized SentinelBridge AlertIngest schemas.
    """

    @classmethod
    def translate_event(cls, event: dict[str, Any]) -> AlertIngest:
        event_id = int(event.get("event_id", 0))
        computer_name = event.get("computer_name", "UNKNOWN-HOST")
        host_ip = event.get("host_ip")
        utc_time_str = event.get("utc_time")

        timestamp = (
            datetime.fromisoformat(utc_time_str).replace(tzinfo=timezone.utc)
            if utc_time_str
            else datetime.now(timezone.utc)
        )

        host_info = HostInfo(hostname=computer_name, ip=host_ip)

        # 1. Sysmon Event ID 1: Process Creation
        if event_id == 1:
            cmd = event.get("command_line", "")
            image = event.get("image", "")
            parent_image = event.get("parent_image", "")
            pid = int(event.get("process_id", 0)) if event.get("process_id") else None
            ppid = int(event.get("parent_process_id", 0)) if event.get("parent_process_id") else None

            process_info = ProcessInfo(
                command_line=cmd,
                process_id=pid,
                parent_process_id=ppid,
                image_path=image,
            )

            # Rule match: PowerShell Obfuscation
            if "powershell" in image.lower() and any(
                f in cmd.lower() for f in ["-enc", "-w hidden", "invoke-expression", "iex("]
            ):
                return AlertIngest(
                    source="sysmon",
                    timestamp=timestamp,
                    severity=AlertSeverity.HIGH,
                    rule_id="SIGMA-T1059.001",
                    title="Suspicious PowerShell Obfuscated Execution",
                    description=f"PowerShell executed with obfuscation flags by parent {parent_image}",
                    host=host_info,
                    process=process_info,
                    raw_payload=event,
                )

            # Rule match: Scheduled Task Persistence
            if "schtasks" in image.lower() and "/create" in cmd.lower():
                return AlertIngest(
                    source="sysmon",
                    timestamp=timestamp,
                    severity=AlertSeverity.HIGH,
                    rule_id="SIGMA-T1053.005",
                    title="Scheduled Task Created via Command Line",
                    description=f"Task persistence configured via schtasks.exe: {cmd}",
                    host=host_info,
                    process=process_info,
                    raw_payload=event,
                )

            # Generic Process Alert fallback
            return AlertIngest(
                source="sysmon",
                timestamp=timestamp,
                severity=AlertSeverity.LOW,
                rule_id="SYSMON-EID1-GENERIC",
                title=f"Process Execution: {image}",
                description=f"Process {image} spawned with commandline: {cmd}",
                host=host_info,
                process=process_info,
                raw_payload=event,
            )

        # 2. Sysmon Event ID 10: Process Access (e.g. LSASS Dump)
        elif event_id == 10:
            source_image = event.get("source_image", "")
            target_image = event.get("target_image", "")
            granted_access = event.get("granted_access", "")

            process_info = ProcessInfo(
                command_line=f"{source_image} -> {target_image} (Access: {granted_access})",
                image_path=source_image,
            )

            if "lsass.exe" in target_image.lower() and any(
                mask in granted_access.lower() for mask in ["0x1010", "0x1038", "0x1438", "0x1f3fff"]
            ):
                return AlertIngest(
                    source="sysmon",
                    timestamp=timestamp,
                    severity=AlertSeverity.CRITICAL,
                    rule_id="SIGMA-T1003.001",
                    title="LSASS Memory Handle Obtained (Credential Access)",
                    description=(
                        f"Process {source_image} acquired high-privilege access {granted_access} "
                        f"to {target_image} for potential memory dump."
                    ),
                    host=host_info,
                    process=process_info,
                    raw_payload=event,
                )

        raise ValueError(f"Unsupported or non-actionable Sysmon event: ID {event_id}")