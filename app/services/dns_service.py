import ipaddress
import re

import dns.exception
import dns.resolver

from app.schemas.dns import DnsLookupError, DnsLookupResponse, DnsRecord, DnsStatus

SUPPORTED_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "CNAME"}
RESERVED_SUFFIXES = {
    "alt",
    "arpa",
    "example",
    "home.arpa",
    "internal",
    "invalid",
    "lan",
    "local",
    "localhost",
    "onion",
    "test",
}
DNS_QUERY_LIFETIME_SECONDS = 2.0
MAX_RECORDS = 20
MAX_RECORD_VALUE_LENGTH = 1024
DOMAIN_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _normalize_domain(domain: str | None) -> str | None:
    if domain is None:
        return None

    normalized_domain = domain.strip().lower()
    if normalized_domain.endswith("."):
        normalized_domain = normalized_domain[:-1]

    try:
        normalized_domain = normalized_domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not normalized_domain or len(normalized_domain) > 253:
        return None

    try:
        ipaddress.ip_address(normalized_domain)
        return None
    except ValueError:
        pass

    labels = normalized_domain.split(".")
    if len(labels) < 2 or any(
        not DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels
    ):
        return None

    top_level_label = labels[-1]
    if not (top_level_label[0].isalpha() or top_level_label.startswith("xn--")):
        return None

    if any(
        normalized_domain == suffix or normalized_domain.endswith(f".{suffix}")
        for suffix in RESERVED_SUFFIXES
    ):
        return None

    return normalized_domain


def _error_result(
    domain: str | None,
    record_type: str,
    status: DnsStatus,
    message: str,
) -> DnsLookupResponse:
    return DnsLookupResponse(
        domain=(domain or "")[:253],
        record_type=record_type[:5],
        status=status,
        records=[],
        error=DnsLookupError(code=status, message=message),
        truncated=False,
    )


def _format_record(record: object, record_type: str) -> str:
    if record_type == "MX":
        return f"{record.preference} {record.exchange.to_text()}"

    if record_type == "TXT":
        return b"".join(record.strings).decode("utf-8", errors="replace")

    return record.to_text()


def lookup_dns(
    domain: str | None,
    record_type: str = "A",
) -> DnsLookupResponse:
    normalized_domain = _normalize_domain(domain)
    normalized_record_type = record_type.strip().upper()

    if normalized_domain is None:
        return _error_result(
            domain,
            normalized_record_type,
            "invalid_domain",
            "Enter a valid public domain name.",
        )

    if normalized_record_type not in SUPPORTED_RECORD_TYPES:
        return _error_result(
            normalized_domain,
            normalized_record_type,
            "invalid_record_type",
            "Choose one of the supported DNS record types.",
        )

    try:
        resolver = dns.resolver.Resolver(configure=True)
        answer = resolver.resolve(
            normalized_domain,
            normalized_record_type,
            search=False,
            lifetime=DNS_QUERY_LIFETIME_SECONDS,
        )
    except dns.resolver.NXDOMAIN:
        return _error_result(
            normalized_domain,
            normalized_record_type,
            "domain_not_found",
            "The domain does not exist.",
        )
    except dns.resolver.NoAnswer:
        return _error_result(
            normalized_domain,
            normalized_record_type,
            "record_not_found",
            "No records of this type were found.",
        )
    except dns.exception.Timeout:
        return _error_result(
            normalized_domain,
            normalized_record_type,
            "timeout",
            "The DNS query timed out.",
        )
    except dns.exception.DNSException:
        return _error_result(
            normalized_domain,
            normalized_record_type,
            "resolver_error",
            "The configured DNS resolver could not complete the query.",
        )

    if answer.rrset is None:
        return _error_result(
            normalized_domain,
            normalized_record_type,
            "record_not_found",
            "No records of this type were found.",
        )

    answer_records = list(answer)
    truncated = len(answer_records) > MAX_RECORDS
    records = []

    for answer_record in answer_records[:MAX_RECORDS]:
        value = _format_record(answer_record, normalized_record_type)
        if len(value) > MAX_RECORD_VALUE_LENGTH:
            value = value[:MAX_RECORD_VALUE_LENGTH]
            truncated = True

        records.append(DnsRecord(value=value, ttl=answer.rrset.ttl))

    return DnsLookupResponse(
        domain=normalized_domain,
        record_type=normalized_record_type,
        status="ok",
        records=records,
        error=None,
        truncated=truncated,
    )