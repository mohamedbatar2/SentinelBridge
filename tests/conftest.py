import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.storage.memory import alert_repository


@pytest.fixture(autouse=True)
def clean_repository():
    alert_repository.clear()
    yield
    alert_repository.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {settings.API_KEY_HEADER: settings.API_KEY}
