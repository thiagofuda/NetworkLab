from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_cidr_api_returns_ipv4_network_information() -> None:
    response = client.get("/api/cidr", params={"cidr": "192.168.10.25/24"})

    assert response.status_code == 200
    assert response.json() == {
        "input": "192.168.10.25/24",
        "ip_version": 4,
        "network_address": "192.168.10.0",
        "prefix_length": 24,
        "total_addresses": "256",
        "netmask": "255.255.255.0",
        "broadcast_address": "192.168.10.255",
    }


def test_cidr_api_returns_ipv6_network_information() -> None:
    response = client.get("/api/cidr", params={"cidr": "2001:db8::1/64"})

    assert response.status_code == 200
    assert response.json() == {
        "input": "2001:db8::1/64",
        "ip_version": 6,
        "network_address": "2001:db8::",
        "prefix_length": 64,
        "total_addresses": "18446744073709551616",
        "netmask": None,
        "broadcast_address": None,
    }


def test_cidr_api_returns_422_for_invalid_input() -> None:
    response = client.get("/api/cidr", params={"cidr": "192.0.2.1/33"})

    assert response.status_code == 422
    assert response.json() == {
        "detail": "Enter a valid IPv4 or IPv6 address with a CIDR prefix."
    }


def test_cidr_api_returns_422_when_prefix_is_missing() -> None:
    response = client.get("/api/cidr", params={"cidr": "192.0.2.1"})

    assert response.status_code == 422
    assert response.json() == {
        "detail": "Enter a valid IPv4 or IPv6 address with a CIDR prefix."
    }


def test_cidr_api_returns_422_when_cidr_is_missing() -> None:
    response = client.get("/api/cidr")

    assert response.status_code == 422


def test_cidr_page_displays_form_without_results() -> None:
    response = client.get("/tools/cidr")

    assert response.status_code == 200
    assert "CIDR Calculator | InfraLab" in response.text
    assert "CIDR Calculator" in response.text
    assert 'name="cidr"' in response.text
    assert "Network details" not in response.text


def test_cidr_page_displays_ipv4_results() -> None:
    response = client.get("/tools/cidr", params={"cidr": "192.168.10.25/24"})

    assert response.status_code == 200
    assert "192.168.10.0" in response.text
    assert "255.255.255.0" in response.text
    assert "192.168.10.255" in response.text


def test_cidr_page_displays_ipv6_results_without_ipv4_fields() -> None:
    response = client.get("/tools/cidr", params={"cidr": "2001:db8::1/64"})

    assert response.status_code == 200
    assert "2001:db8::" in response.text
    assert "18446744073709551616" in response.text
    assert "Netmask" not in response.text
    assert "Broadcast address" not in response.text


def test_cidr_page_shows_clear_error_and_escapes_input() -> None:
    invalid_cidr = "<script>alert('test')</script>"
    response = client.get("/tools/cidr", params={"cidr": invalid_cidr})

    assert response.status_code == 200
    assert "Enter a valid IPv4 or IPv6 address with a CIDR prefix." in response.text
    assert invalid_cidr not in response.text
    assert "&lt;script&gt;" in response.text