"""
Safe, non-destructive Atomic Red Team-style emulation scenarios.
These generate representative Sysmon telemetry without harming the host system.
"""

from typing import Any


class AtomicEmulations:
    @staticmethod
    def emulate_powershell_encoded_command() -> dict[str, Any]:
        """
        MITRE ATT&CK: T1059.001 / T1027
        Simulates an obfuscated PowerShell execution.
        """
        return {
            "technique_id": "T1059.001",
            "name": "PowerShell Encoded Command Execution",
            "telemetry": {
                "event_id": 1,
                "computer_name": "WIN-SRV-AD01",
                "host_ip": "192.168.1.10",
                "utc_time": "2026-10-01T22:15:00Z",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
                "parent_image": "C:\\Windows\\System32\\cmd.exe",
                "process_id": 6120,
                "parent_process_id": 1104,
            },
        }

    @staticmethod
    def emulate_schtasks_persistence() -> dict[str, Any]:
        """
        MITRE ATT&CK: T1053.005
        Simulates scheduled task persistence creation.
        """
        return {
            "technique_id": "T1053.005",
            "name": "Scheduled Task Creation for Persistence",
            "telemetry": {
                "event_id": 1,
                "computer_name": "WIN-SRV-AD01",
                "host_ip": "192.168.1.10",
                "utc_time": "2026-10-01T22:16:00Z",
                "image": "C:\\Windows\\System32\\schtasks.exe",
                "command_line": "schtasks.exe /create /tn \"SecurityUpdate\" /tr \"powershell.exe -w hidden -enc...\" /sc onstart /ru system",
                "parent_image": "C:\\Windows\\System32\\cmd.exe",
                "process_id": 7188,
                "parent_process_id": 1104,
            },
        }

    @staticmethod
    def emulate_lsass_credential_access() -> dict[str, Any]:
        """
        MITRE ATT&CK: T1003.001
        Simulates credential harvesting handle acquisition against lsass.exe.
        """
        return {
            "technique_id": "T1003.001",
            "name": "LSASS Process Memory Handle Acquisition",
            "telemetry": {
                "event_id": 10,
                "computer_name": "WIN-SRV-AD01",
                "host_ip": "192.168.1.10",
                "utc_time": "2026-10-01T22:17:00Z",
                "source_image": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\procdump.exe",
                "target_image": "C:\\Windows\\System32\\lsass.exe",
                "granted_access": "0x1F3FFF",
                "call_trace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d454",
            },
        }