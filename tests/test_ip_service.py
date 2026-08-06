from app.services.ip_service import REDACTED_HEADER_VALUE, get_ip_information


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


def test_ip_service_redacts_sensitive_headers() -> None:
    # Valida a regra de seguranca que protege dados sensiveis em headers.
    ip_information = get_ip_information(
        client_ip_address="127.0.0.1",
        user_agent="NetworkLab Test",
        headers={
            "authorization": "Bearer secret-token",
            "cookie": "session=secret-value",
            "x-test-header": "visible-value",
        },
    )

    assert ip_information.headers["authorization"] == REDACTED_HEADER_VALUE
    assert ip_information.headers["cookie"] == REDACTED_HEADER_VALUE
    assert ip_information.headers["x-test-header"] == "visible-value"

