from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelBridge"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"

    # Security: Default to local development key; MUST be overridden in production
    API_KEY: str = "sb-dev-key-insecure-change-in-prod"
    API_KEY_HEADER: str = "X-Sentinel-Key"

    # Environment
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


settings = Settings()
