from datetime import datetime

from pydantic import BaseModel


class IpInformation(BaseModel):
    ip_address: str
    user_agent: str
    headers: dict[str, str]
    requested_at: datetime
