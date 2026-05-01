from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "OTC Secure Comm"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    DATABASE_URL: str = "sqlite+aiosqlite:///./otc_saas.db"

    JWT_SECRET: str = "CHANGE_ME"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TTL: int = 3600       # 1 hour
    JWT_REFRESH_TTL: int = 604800    # 7 days

    OTC_DEFAULT_TTL: int = 1800      # 30 minutes
    OTC_MAX_TTL: int = 86400         # 24 hours

    RATE_LIMIT_PER_MINUTE: int = 60

    ADMIN_EMAIL: str = "admin@localhost"
    ADMIN_PASSWORD: str = "CHANGE_ME"

    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8080"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
