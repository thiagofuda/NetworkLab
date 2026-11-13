from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.resolver
import pytest

from app.services import dns_service
from app.services.dns_service import lookup_dns


def mock_resolver(
    monkeypatch: pytest.MonkeyPatch,
    answer: object = None,
    error: Exception | None = None,
) -> MagicMock:
    resolver = MagicMock()
    resolver.resolve.return_value = answer
    if error is not None:
        resolver.resolve.side_effect = error
    monkeypatch.setattr(
        dns_service.dns.resolver,
        "Resolver",
        MagicMock(return_value=resolver),
    )
    return resolver


def mock_answer(records: list[object], ttl: int = 300) -> MagicMock:
    answer = MagicMock()
    answer.rrset.ttl = ttl
    answer.__iter__.return_value = iter(records)
    return answer


@pytest.mark.parametrize(
    ("record_type", "record", "expected_value"),
    [
        ("A", SimpleNamespace(to_text=lambda: "203.0.113.10"), "203.0.113.10"),
        ("AAAA", SimpleNamespace(to_text=lambda: "2001:db8::10"), "2001:db8::10"),
        (
            "CNAME",
            SimpleNamespace(to_text=lambda: "target.example.net."),
            "target.example.net.",
        ),
        (
            "MX",
            SimpleNamespace(
                preference=10,
                exchange=SimpleNamespace(to_text=lambda: "mail.example.net."),
            ),
            "10 mail.example.net.",
        ),
        ("TXT", SimpleNamespace(strings=(b"v=spf1 ", b"~all")), "v=spf1 ~all"),
    ],
)
def test_lookup_formats_supported_record_types(
    monkeypatch: pytest.MonkeyPatch,
    record_type: str,
    record: object,
    expected_value: str,
) -> None:
    resolver = mock_resolver(monkeypatch, answer=mock_answer([record]))

    result = lookup_dns("Example.COM.", record_type)

    assert result.domain == "example.com"
    assert result.record_type == record_type
    assert result.status == "ok"
    assert result.records[0].value == expected_value
    assert result.records[0].ttl == 300
    assert result.error is None
    resolver.resolve.assert_called_once_with(
        "example.com",
        record_type,
        search=False,
        lifetime=dns_service.DNS_QUERY_LIFETIME_SECONDS,
    )


@pytest.mark.parametrize(
    "domain",
    [
        None,
        "",
        "localhost",
        "host.local",
        "service.internal",
        "metadata.google.internal",
        "example.test",
        "127.0.0.1",
        "https://example.com",
        "bad_label.example.com",
    ],
)
def test_lookup_rejects_invalid_or_special_domains(
    monkeypatch: pytest.MonkeyPatch,
    domain: str | None,
) -> None:
    resolver = mock_resolver(monkeypatch)

    result = lookup_dns(domain)

    assert result.status == "invalid_domain"
    assert result.error is not None
    resolver.resolve.assert_not_called()


def test_lookup_rejects_unsupported_record_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = mock_resolver(monkeypatch)

    result = lookup_dns("example.com", "ANY")

    assert result.status == "invalid_record_type"
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize(
    ("resolver_error", "expected_status"),
    [
        (dns.resolver.NXDOMAIN(), "domain_not_found"),
        (dns.resolver.NoAnswer(), "record_not_found"),
        (
            dns.resolver.LifetimeTimeout(timeout=2.0, errors=[]),
            "timeout",
        ),
        (
            dns.resolver.NoNameservers(request=MagicMock(), errors=[]),
            "resolver_error",
        ),
    ],
)
def test_lookup_maps_resolver_errors_to_safe_statuses(
    monkeypatch: pytest.MonkeyPatch,
    resolver_error: Exception,
    expected_status: str,
) -> None:
    mock_resolver(monkeypatch, error=resolver_error)

    result = lookup_dns("example.com", "A")

    assert result.status == expected_status
    assert result.records == []
    assert result.error is not None
    assert str(resolver_error) not in result.error.message


def test_lookup_limits_number_and_size_of_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [
        SimpleNamespace(to_text=lambda index=index: f"203.0.113.{index}")
        for index in range(dns_service.MAX_RECORDS + 1)
    ]
    records[-1] = SimpleNamespace(
        to_text=lambda: "x" * (dns_service.MAX_RECORD_VALUE_LENGTH + 1)
    )
    mock_resolver(monkeypatch, answer=mock_answer(records))

    result = lookup_dns("example.com", "A")

    assert len(result.records) == dns_service.MAX_RECORDS
    assert all(
        len(record.value) <= dns_service.MAX_RECORD_VALUE_LENGTH
        for record in result.records
    )
    assert result.truncated is True
