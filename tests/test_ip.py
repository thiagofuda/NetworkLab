from datetime import datetime

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ip_page_displays_request_information() -> None:
    # Valida a renderizacao da interface HTML com dados principais da requisicao.
    response = client.get(
        "/tools/ip",
        headers={"User-Agent": "NetworkLab Test", "X-Test-Header": "test-value"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "IP Information" in response.text
    assert "testclient" in response.text
    assert "NetworkLab Test" in response.text
    assert "x-test-header" in response.text
    assert "test-value" in response.text


def test_ip_api_returns_request_information_as_json() -> None:
    # Valida o contrato JSON consumivel por clientes externos.
    response = client.get(
        "/api/ip",
        headers={"User-Agent": "NetworkLab Test", "X-Test-Header": "test-value"},
    )

    response_data = response.json()

    assert response.status_code == 200
    assert response_data["ip_address"] == "testclient"
    assert response_data["user_agent"] == "NetworkLab Test"
    assert response_data["headers"]["x-test-header"] == "test-value"
    assert datetime.fromisoformat(response_data["requested_at"]).tzinfo is not None


def test_ip_page_escapes_header_html() -> None:
    # Confirma que o template nao reflete HTML bruto enviado pelo cliente.
    response = client.get(
        "/tools/ip",
        headers={"X-Test-Header": "<script>alert('test')</script>"},
    )

    assert response.status_code == 200
    assert "<script>alert('test')</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_ip_api_does_not_expose_sensitive_headers() -> None:
    # Garante que cabecalhos sensiveis sao mascarados na resposta publica.
    response = client.get(
        "/api/ip",
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 200
    assert response.json()["headers"]["authorization"] == "[REDACTED]"
    assert "secret-token" not in response.text
