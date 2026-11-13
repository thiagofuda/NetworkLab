from typing import Literal

from pydantic import BaseModel

DnsStatus = Literal[
    "ok",
    "invalid_domain",
    "invalid_record_type",
    "domain_not_found",
    "record_not_found",
    "timeout",
    "resolver_error",
]


class DnsRecord(BaseModel):
    value: str
    ttl: int | None


class DnsLookupError(BaseModel):
    code: str
    message: str


class DnsLookupResponse(BaseModel):
    domain: str
    record_type: str
    status: DnsStatus
    records: list[DnsRecord]
    error: DnsLookupError | None
    truncated: bool
