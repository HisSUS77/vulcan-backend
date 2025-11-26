from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    ENV: str = Field(default="dev")
    API_V1_STR: str = Field(default="/api/v1")
    PROJECT_NAME: str = Field(default="VULCAN API")
    BACKEND_CORS_ORIGINS: str = Field(default="http://localhost:3000")

    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./vulcan.db")

    JWT_SECRET: str = Field(default="change-me-super-secret")
    JWT_ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60)
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(default=43200)

    DEFAULT_ADMIN_EMAIL: str = Field(default="admin@vulcan.ai")
    DEFAULT_ADMIN_PASSWORD: str = Field(default="admin123!")


settings = Settings()
