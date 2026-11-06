from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import get_settings
from app.routers.home import router as home_router
from app.routers.ip import router as ip_router


def create_app() -> FastAPI:
    # Centraliza a criação da aplicação para facilitar testes e futura evolução.
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        debug=settings.app_debug,
        version="0.1.0",
    )
    # Cada router é registrado aqui para manter o ponto de entrada explícito.
    application.include_router(home_router)
    application.include_router(api_router)
    application.include_router(ip_router)
    return application


app = create_app()

