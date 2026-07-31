from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import get_settings


def app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        debug=settings.app_debug,
        version="0.1.0",
    )
    application.include_router(api_router)
    return application


app = app()

