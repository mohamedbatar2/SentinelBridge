import pytest
from fastapi import status


def test_metrics_unauthorized(client):
    response = client.get("/api/v1/metrics")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_metrics_authorized_empty(client, auth_headers):
    response = client.get("/api/v1/metrics", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "total_alerts" in data
    assert "escalation_rate_percent" in data