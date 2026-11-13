from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.router import api_router
from app.core.config import get_settings
from app.routers.cidr import router as cidr_router
from app.routers.dns import router as dns_router
from app.routers.home import router as home_router
from app.routers.ip import router as ip_router


def create_app() -> FastAPI:
    # Centraliza a criação da aplicação para facilitar testes e futura evolução.
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        description=(
            "Simple, open-source tools for infrastructure troubleshooting, "
            "cloud operations, and automation."
        ),
        debug=settings.app_debug,
        version="0.1.0",
    )
    static_directory = Path(__file__).parent / "static"
    application.mount(
        "/static",
        StaticFiles(directory=static_directory),
        name="static",
    )
    # Cada router é registrado aqui para manter o ponto de entrada explícito.
    application.include_router(home_router)
    application.include_router(cidr_router)
    application.include_router(dns_router)
    application.include_router(api_router)
    application.include_router(ip_router)
    return application


app = create_app()


