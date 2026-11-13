from pathlib import Path

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

templates_directory = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=templates_directory)
ROBOTS_TEXT = "User-agent: *\nAllow: /\n"


@router.get(
    "/",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def show_home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={},
    )


@router.get(
    "/about",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def show_about(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="about.html",
        context={},
    )


@router.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)
async def read_robots_file() -> PlainTextResponse:
    return PlainTextResponse(ROBOTS_TEXT)
