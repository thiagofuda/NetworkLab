import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ip_page_displays_request_information() -> None:
    response = client.get(
        "/tools/ip",
        headers={"User-Agent": "NetworkLab Test", "Accept-Language": "en-US"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "IP Information | InfraLab" in response.text
    assert "IP Information" in response.text
    assert "testclient" in response.text
    assert "NetworkLab Test" in response.text
    assert "accept-language" in response.text
    assert "en-US" in response.text
    assert "x-test-header" not in response.text


@pytest.mark.parametrize("ip_address", ["203.0.113.10", "2001:db8::1"])
def test_ip_api_returns_only_client_ip_as_plain_text(ip_address: str) -> None:
    ip_client = TestClient(app, client=(ip_address, 12345))
    response = ip_client.get("/api/ip")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == ip_address


def test_ip_api_openapi_documents_plain_text() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    content = response.json()["paths"]["/api/ip"]["get"]["responses"]["200"]["content"]
    assert "text/plain" in content
    assert "application/json" not in content


def test_ip_page_escapes_header_html() -> None:
    response = client.get(
        "/tools/ip",
        headers={"Accept-Language": "<script>alert('test')</script>"},
    )

    assert response.status_code == 200
    assert "<script>alert('test')</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_ip_page_only_exposes_allowlisted_headers() -> None:
    response = client.get(
        "/tools/ip",
        headers={
            "Authorization": "Bearer secret-token",
            "Cookie": "session=secret-value",
            "X-Auth-Token": "custom-secret",
            "Accept": "text/html",
        },
    )

    assert response.status_code == 200
    assert "accept" in response.text
    assert "text/html" in response.text
    assert "authorization" not in response.text
    assert "cookie" not in response.text
    assert "x-auth-token" not in response.text
    assert "secret-token" not in response.text
    assert "secret-value" not in response.text
    assert "custom-secret" not in response.text
