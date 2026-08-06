from collections.abc import Mapping
from datetime import UTC, datetime

from app.schemas.ip import IpInformation

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
}
REDACTED_HEADER_VALUE = "[REDACTED]"


def get_ip_information(
    client_ip_address: str | None,
    user_agent: str | None,
    headers: Mapping[str, str],
) -> IpInformation:
    # Reduz risco de vazamento de dados sensíveis em respostas e logs.
    safe_headers = {
        name: REDACTED_HEADER_VALUE if name.lower() in SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }

    return IpInformation(
        ip_address=client_ip_address or "unknown",
        user_agent=user_agent or "unknown",
        headers=safe_headers,
        # Padroniza o timestamp em UTC para evitar ambiguidades entre fusos.
        requested_at=datetime.now(UTC),
    )

