from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.resolver
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import dns_service

client = TestClient(app)


def mock_resolver(
    monkeypatch: pytest.MonkeyPatch,
    records: list[object] | None = None,
    error: Exception | None = None,
) -> MagicMock:
    resolver = MagicMock()
    answer = MagicMock()
    answer.rrset.ttl = 300
    answer.__iter__.return_value = iter(records or [])
    resolver.resolve.return_value = answer
    if error is not None:
        resolver.resolve.side_effect = error

    monkeypatch.setattr(
        dns_service.dns.resolver,
        "Resolver",
        MagicMock(return_value=resolver),
    )
    return resolver


def test_dns_api_returns_records_and_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_resolver(
        monkeypatch,
        records=[SimpleNamespace(to_text=lambda: "203.0.113.10")],
    )

    response = client.get(
        "/api/dns",
        params={"domain": "Example.COM.", "record_type": "a"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "domain": "example.com",
        "record_type": "A",
        "status": "ok",
        "records": [{"value": "203.0.113.10", "ttl": 300}],
        "error": None,
        "truncated": False,
    }


@pytest.mark.parametrize(
    ("resolver_error", "expected_status", "expected_http_status"),
    [
        (dns.resolver.NXDOMAIN(), "domain_not_found", 404),
        (dns.resolver.NoAnswer(), "record_not_found", 404),
        (
            dns.resolver.LifetimeTimeout(timeout=2.0, errors=[]),
            "timeout",
            504,
        ),
        (
            dns.resolver.NoNameservers(request=MagicMock(), errors=[]),
            "resolver_error",
            502,
        ),
    ],
)
def test_dns_api_returns_safe_resolver_errors(
    monkeypatch: pytest.MonkeyPatch,
    resolver_error: Exception,
    expected_status: str,
    expected_http_status: int,
) -> None:
    mock_resolver(monkeypatch, error=resolver_error)

    response = client.get("/api/dns", params={"domain": "example.com"})

    assert response.status_code == expected_http_status
    assert response.json()["status"] == expected_status
    assert response.json()["records"] == []
    assert str(resolver_error) not in response.text


def test_dns_api_rejects_special_domain_without_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = mock_resolver(monkeypatch)

    response = client.get("/api/dns", params={"domain": "metadata.google.internal"})

    assert response.status_code == 422
    assert response.json()["status"] == "invalid_domain"
    resolver.resolve.assert_not_called()


def test_dns_page_shows_form_without_query(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = mock_resolver(monkeypatch)

    response = client.get("/tools/dns")

    assert response.status_code == 200
    assert "DNS Lookup" in response.text
    assert 'name="domain"' in response.text
    assert "DNS lookup results" not in response.text
    resolver.resolve.assert_not_called()


def test_dns_page_displays_records_and_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_resolver(
        monkeypatch,
        records=[SimpleNamespace(to_text=lambda: "mail.example.com.")],
    )

    response = client.get(
        "/tools/dns",
        params={"domain": "example.com", "record_type": "CNAME"},
    )

    assert response.status_code == 200
    assert "mail.example.com." in response.text
    assert "300" in response.text