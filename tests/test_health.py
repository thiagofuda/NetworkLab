from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import app, create_app

client = TestClient(app)


def test_health_check() -> None:
    # Garante o contrato minimo do endpoint de health para monitoramento.
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_uses_infralab_identity(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.main.get_settings",
        lambda: Settings(app_name="InfraLab"),
    )
    response = TestClient(create_app()).get("/openapi.json")
    api_info = response.json()["info"]

    assert response.status_code == 200
    assert api_info["title"] == "InfraLab"
    assert "infrastructure troubleshooting" in api_info["description"]

    documented_paths = response.json()["paths"]
    hidden_paths = {
        "/",
        "/about",
        "/robots.txt",
        "/health",
        "/tools/ip",
        "/tools/cidr",
        "/tools/dns",
    }
    api_paths = {"/api/ip", "/api/cidr", "/api/dns"}

    assert hidden_paths.isdisjoint(documented_paths)
    assert api_paths.issubset(documented_paths)
