from pydantic import BaseModel


class CidrInformation(BaseModel):
    input: str
    ip_version: int
    network_address: str
    prefix_length: int
    total_addresses: str
    netmask: str | None
    broadcast_address: str | None