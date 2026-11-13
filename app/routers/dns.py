from pathlib import Path

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.schemas.dns import DnsLookupResponse
from app.services.dns_service import SUPPORTED_RECORD_TYPES, lookup_dns

router = APIRouter()
templates_directory = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=templates_directory)

HTTP_STATUS_BY_DNS_STATUS = {
    "ok": status.HTTP_200_OK,
    "invalid_domain": 422,
    "invalid_record_type": 422,
    "domain_not_found": status.HTTP_404_NOT_FOUND,
    "record_not_found": status.HTTP_404_NOT_FOUND,
    "timeout": status.HTTP_504_GATEWAY_TIMEOUT,
    "resolver_error": status.HTTP_502_BAD_GATEWAY,
}


@router.get("/tools/dns", response_class=HTMLResponse, include_in_schema=False)
async def show_dns_lookup(
    request: Request,
    domain: str | None = None,
    record_type: str = "A",
) -> HTMLResponse:
    dns_result = lookup_dns(domain, record_type) if domain is not None else None

    return templates.TemplateResponse(
        request=request,
        name="dns.html",
        context={
            "domain": domain or "",
            "record_type": record_type.upper(),
            "record_types": sorted(SUPPORTED_RECORD_TYPES),
            "dns_result": dns_result,
        },
    )


@router.get("/api/dns", response_model=DnsLookupResponse)
async def read_dns_lookup(
    response: Response,
    domain: str | None = None,
    record_type: str = "A",
) -> DnsLookupResponse:
    dns_result = lookup_dns(domain, record_type)
    response.status_code = HTTP_STATUS_BY_DNS_STATUS[dns_result.status]
    return dns_result
