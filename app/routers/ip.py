from pathlib import Path

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.schemas.ip import IpInformation
from app.services.ip_service import get_ip_information

router = APIRouter()

# Resolve o caminho do diretório de templates relativo ao pacote para funcionar em diferentes ambientes.
templates_directory = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=templates_directory)


def get_request_ip_information(request: Request) -> IpInformation:
    # Isola a extração dos dados da requisição para reaproveitar nas rotas HTML e JSON.
    client_ip_address = request.client.host if request.client else None
    return get_ip_information(
        client_ip_address=client_ip_address,
        user_agent=request.headers.get("user-agent"),
        headers=request.headers,
    )


@router.get("/tools/ip", response_class=HTMLResponse, status_code=status.HTTP_200_OK)
async def show_ip_information(request: Request) -> HTMLResponse:
    ip_information = get_request_ip_information(request)
    return templates.TemplateResponse(
        request=request,
        name="ip.html",
        context={"ip_information": ip_information},
    )


@router.get(
    "/api/ip",
    response_model=IpInformation,
    status_code=status.HTTP_200_OK,
)
async def read_ip_information(request: Request) -> IpInformation:
    return get_request_ip_information(request)

