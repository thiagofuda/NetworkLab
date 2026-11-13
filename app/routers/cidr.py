from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.schemas.cidr import CidrInformation
from app.services.cidr_service import calculate_cidr

router = APIRouter()
templates_directory = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=templates_directory)
INVALID_CIDR_MESSAGE = "Enter a valid IPv4 or IPv6 address with a CIDR prefix."


@router.get("/tools/cidr", response_class=HTMLResponse, include_in_schema=False)
async def show_cidr_calculator(
    request: Request,
    cidr: str | None = None,
) -> HTMLResponse:
    cidr_information = None
    error_message = None

    if cidr is not None:
        try:
            cidr_information = calculate_cidr(cidr)
        except ValueError:
            error_message = INVALID_CIDR_MESSAGE

    return templates.TemplateResponse(
        request=request,
        name="cidr.html",
        context={
            "cidr": cidr or "",
            "cidr_information": cidr_information,
            "error_message": error_message,
        },
    )


@router.get(
    "/api/cidr",
    response_model=CidrInformation,
    status_code=status.HTTP_200_OK,
)
async def read_cidr_information(cidr: str | None = None) -> CidrInformation:
    try:
        return calculate_cidr(cidr or "")
    except ValueError as error:
        # Converte entrada invalida em uma resposta HTTP clara.
        raise HTTPException(
            status_code=422,
            detail=INVALID_CIDR_MESSAGE,
        ) from error
