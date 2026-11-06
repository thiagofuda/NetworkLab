from collections.abc import Mapping
from datetime import UTC, datetime

from app.schemas.ip import IpInformation

DISPLAYED_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "host",
}


def get_ip_information(
    client_ip_address: str | None,
    user_agent: str | None,
    headers: Mapping[str, str],
) -> IpInformation:
    # Expõe somente metadados comuns, evitando headers customizados com segredos.
    displayed_headers = {
        name: value
        for name, value in headers.items()
        if name.lower() in DISPLAYED_HEADERS
    }

    return IpInformation(
        ip_address=client_ip_address or "unknown",
        user_agent=user_agent or "unknown",
        headers=displayed_headers,
        # Padroniza o timestamp em UTC para evitar ambiguidades entre fusos.
        requested_at=datetime.now(UTC),
    )

