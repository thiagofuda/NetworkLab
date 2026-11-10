import pytest

from app.services.cidr_service import calculate_cidr


def test_calculate_ipv4_network() -> None:
    cidr_information = calculate_cidr("192.168.10.25/24")

    assert cidr_information.ip_version == 4
    assert cidr_information.network_address == "192.168.10.0"
    assert cidr_information.prefix_length == 24
    assert cidr_information.total_addresses == "256"
    assert cidr_information.netmask == "255.255.255.0"
    assert cidr_information.broadcast_address == "192.168.10.255"


def test_calculate_ipv6_network() -> None:
    cidr_information = calculate_cidr("2001:db8::1/64")

    assert cidr_information.ip_version == 6
    assert cidr_information.network_address == "2001:db8::"
    assert cidr_information.prefix_length == 64
    assert cidr_information.total_addresses == "18446744073709551616"
    assert cidr_information.netmask is None
    assert cidr_information.broadcast_address is None


@pytest.mark.parametrize(
    ("cidr", "total_addresses"),
    [("192.0.2.0/31", "2"), ("192.0.2.1/32", "1")],
)
def test_ipv4_small_prefixes_have_no_broadcast(
    cidr: str,
    total_addresses: str,
) -> None:
    cidr_information = calculate_cidr(cidr)

    assert cidr_information.total_addresses == total_addresses
    assert cidr_information.broadcast_address is None


@pytest.mark.parametrize(
    ("cidr", "total_addresses"),
    [("2001:db8::/127", "2"), ("2001:db8::1/128", "1")],
)
def test_ipv6_small_prefixes_have_no_broadcast(
    cidr: str,
    total_addresses: str,
) -> None:
    cidr_information = calculate_cidr(cidr)

    assert cidr_information.total_addresses == total_addresses
    assert cidr_information.broadcast_address is None


@pytest.mark.parametrize(
    "cidr",
    ["not-an-ip", "192.0.2.1", "192.0.2.1/33", "2001:db8::1/129", "192.0.2.1/-1"],
)
def test_invalid_cidr_raises_value_error(cidr: str) -> None:
    with pytest.raises(ValueError):
        calculate_cidr(cidr)