from app.services.ip_service import get_ip_information


def test_ip_service_handles_missing_client_and_user_agent() -> None:
    # Define fallback previsivel quando a requisicao nao traz metadados esperados.
    ip_information = get_ip_information(
        client_ip_address=None,
        user_agent=None,
        headers={},
    )

    assert ip_information.ip_address == "unknown"
    assert ip_information.user_agent == "unknown"
    assert ip_information.headers == {}


def test_ip_service_returns_only_allowlisted_headers() -> None:
    # Evita publicar headers de autenticacao ou campos customizados desconhecidos.
    ip_information = get_ip_information(
        client_ip_address="127.0.0.1",
        user_agent="NetworkLab Test",
        headers={
            "authorization": "Bearer secret-token",
            "cookie": "session=secret-value",
            "x-auth-token": "custom-secret",
            "accept-language": "en-US",
        },
    )

    assert ip_information.headers == {"accept-language": "en-US"}

