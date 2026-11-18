from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    app_name: str = "InfraLab"
    app_env: Literal["development", "test", "production"] = "development"
    app_debug: bool = False
    # SecretStr evita que a chave apareca por acidente em representacoes do objeto.
    gemini_api_key: SecretStr = SecretStr("")
    # Pode ser substituido no ambiente sem alterar o codigo.
    gemini_model: str = "gemini-3.5-flash-lite"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    # Reaproveita a mesma instancia de configuracao durante o ciclo da aplicacao.
    return Settings()

