# SentinelBridge
### Mini-SOAR & Detection Engineering Platform

SentinelBridge is a modular Security Orchestration, Automation, and Response (SOAR) and Detection Engineering pipeline designed for automated alert triage, context enrichment, and incident response operations.

---

## Architecture & Data Flow

```mermaid
graph TD
    A[Endpoint Telemetry: Sysmon / Event Logs] -->|Log Collector / Sigma| B[SysmonTelemetryTranslator]
    B -->|POST /api/v1/alerts| C[FastAPI Ingestion Engine]
    C -->|Sanitize & Validate| D[Pydantic V2 Normalizer]
    D -->|Text Corpus Extraction| E[IoC Extraction Engine]
    E -->|OPSEC Filter / Public IPs| F[Threat Intelligence Provider]
    F -->|Reputation Data| G[MITRE ATT&CK Mapper]
    G -->|Tactic & Technique Rules| H[Explainable Risk Engine]
    H -->|Risk Score >= 70 / Critical| I[Incident Promotion Engine]
    I -->|Ticket Generation| J[Ticketing Connector: Local / TheHive]
    I -->|Notification Dispatch| K[Notification Provider: Console / Webhook]