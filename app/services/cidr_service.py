import ipaddress

from app.schemas.cidr import CidrInformation


def calculate_cidr(cidr: str) -> CidrInformation:
    # Exige o prefixo para nao assumir /32 ou /128 automaticamente.
    if "/" not in cidr:
        raise ValueError("A CIDR prefix is required.")

    # Normaliza o IP informado para o endereco inicial da rede.
    network = ipaddress.ip_network(cidr, strict=False)
    is_ipv4 = isinstance(network, ipaddress.IPv4Network)
    # O contrato nao apresenta broadcast em redes IPv4 /31 e /32.
    has_broadcast = is_ipv4 and network.prefixlen < 31

    return CidrInformation(
        input=cidr,
        ip_version=network.version,
        network_address=str(network.network_address),
        prefix_length=network.prefixlen,
        total_addresses=str(network.num_addresses),
        netmask=str(network.netmask) if is_ipv4 else None,
        broadcast_address=str(network.broadcast_address) if has_broadcast else None,
    )