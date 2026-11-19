from pathlib import Path

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates

router = APIRouter()

templates_directory = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=templates_directory)
ROBOTS_TEXT = (
    "User-agent: *\n"
    "Allow: /\n"
    "Sitemap: https://infralab.fuda.com.br/sitemap.xml\n"
)

# Lista apenas as paginas HTML publicas que devem aparecer nas buscas.
SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://infralab.fuda.com.br/</loc></url>
  <url><loc>https://infralab.fuda.com.br/about</loc></url>
  <url><loc>https://infralab.fuda.com.br/tools/ip</loc></url>
  <url><loc>https://infralab.fuda.com.br/tools/cidr</loc></url>
  <url><loc>https://infralab.fuda.com.br/tools/dns</loc></url>
</urlset>
"""


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


@router.get("/sitemap.xml", include_in_schema=False)
async def read_sitemap() -> Response:
    return Response(SITEMAP_XML, media_type="application/xml")
