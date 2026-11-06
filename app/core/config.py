from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NetworkLab API"
    app_env: Literal["development", "test", "production"] = "development"
    app_debug: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    # Reaproveita a mesma instancia de configuracao durante o ciclo da aplicacao.
    return Settings()

