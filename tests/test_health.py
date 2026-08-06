from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_check() -> None:
    # Garante o contrato minimo do endpoint de health para monitoramento.
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
