from datetime import datetime

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ip_page_displays_request_information() -> None:
    # Valida a renderizacao da interface HTML com dados principais da requisicao.
    response = client.get(
        "/tools/ip",
        headers={"User-Agent": "NetworkLab Test", "Accept-Language": "en-US"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "IP Information" in response.text
    assert "testclient" in response.text
    assert "NetworkLab Test" in response.text
    assert "accept-language" in response.text
    assert "en-US" in response.text
    assert "x-test-header" not in response.text


def test_ip_api_returns_request_information_as_json() -> None:
    # Valida o contrato JSON consumivel por clientes externos.
    response = client.get(
        "/api/ip",
        headers={"User-Agent": "NetworkLab Test", "Accept-Language": "en-US"},
    )

    response_data = response.json()

    assert response.status_code == 200
    assert response_data["ip_address"] == "testclient"
    assert response_data["user_agent"] == "NetworkLab Test"
    assert response_data["headers"]["accept-language"] == "en-US"
    assert datetime.fromisoformat(response_data["requested_at"]).tzinfo is not None


def test_ip_page_escapes_header_html() -> None:
    # Confirma que o template nao reflete HTML bruto enviado pelo cliente.
    response = client.get(
        "/tools/ip",
        headers={"Accept-Language": "<script>alert('test')</script>"},
    )

    assert response.status_code == 200
    assert "<script>alert('test')</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_ip_api_only_exposes_allowlisted_headers() -> None:
    # Garante que headers de autenticacao e headers customizados nao sao publicados.
    response = client.get(
        "/api/ip",
        headers={
            "Authorization": "Bearer secret-token",
            "Cookie": "session=secret-value",
            "X-Auth-Token": "custom-secret",
            "Accept": "text/html",
        },
    )

    assert response.status_code == 200
    response_headers = response.json()["headers"]

    assert response_headers["accept"] == "text/html"
    assert "authorization" not in response_headers
    assert "cookie" not in response_headers
    assert "x-auth-token" not in response_headers
    assert "secret-token" not in response.text
    assert "secret-value" not in response.text
    assert "custom-secret" not in response.text
