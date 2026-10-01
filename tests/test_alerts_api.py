import json
from pathlib import Path

from fastapi import status


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "healthy"


def test_ingest_alert_missing_auth(client):
    payload = {"source": "test"}
    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_ingest_alert_invalid_schema(client, auth_headers):
    payload = {
        "source": "wazuh",
        "severity": "high",
        "rule_id": "1001",
    }
    response = client.post("/api/v1/alerts", json=payload, headers=auth_headers)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_ingest_alert_success(client, auth_headers):
    sample_file = Path("sample_alerts/wazuh_powershell.json")
    with open(sample_file, "r", encoding="utf-8-sig") as f:
        payload = json.load(f)

    response = client.post("/api/v1/alerts", json=payload, headers=auth_headers)
    assert response.status_code == status.HTTP_202_ACCEPTED

    data = response.json()
    assert "alert_id" in data
    assert data["status"] == "accepted"
    assert data["message"] == "Alert accepted for processing"
