"""
Configuration management for FastAPI application
Loads from environment variables with validation
Use pydantic-settings for type-safe config
"""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List
import secrets


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables
    Security: Never commit secrets to version control
    """
    model_config = SettingsConfigDict(
        # env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # --- Application Metadata ---
    ENVIRONMENT: str = os.getenv("hml")
    DEBUG: str = os.getenv("DEBUG")
    PROJECT_NAME: str = os.getenv("PROJECT_NAME")
    VERSION: str = os.getenv("VERSION")
    API_V1_STR: str = f"/api/{VERSION}"

    # --- Security & JWT Configuration ---
    # To generate a good secret key: openssl rand -hex 32
    API_KEY: str = os.getenv("API_KEY")
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32) # os.getenv("SECRET_KEY")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM")
    JWT_ISSUER: str = os.getenv("JWT_ISSUER")
    JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE")

    # Token Lifetimes (in seconds)
    ACCESS_TOKEN_EXPIRE_SECONDS: int = os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS")
    REFRESH_TOKEN_EXPIRE_SECONDS: int = os.getenv("REFRESH_TOKEN_EXPIRE_SECONDS")

    # Cookie Configuration
    COOKIE_DOMAIN: str = "localhost" # ".yourapp.com"  # Allows subdomains
    # For localhost: "localhost"

    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "https://yourapp.com",
        "https://www.yourapp.com",
        # For development: "http://localhost:4200"
    ]

    # Security
    ALLOWED_HOSTS: List[str] = [
        "yourapp.com",
        "www.yourapp.com",
        "api.yourapp.com"
    ]

    FRONTEND_URL: str = os.getenv("FRONTEND_URL")

    # Google OAuth
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI: str = os.getenv(f"{FRONTEND_URL}/auth/callback/google")
    GOOGLE_TOKEN_URL: str = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL: str = "https://www.googleapis.com/oauth2/v3/userinfo"
    GOOGLE_JWKS_URL: str = "https://www.googleapis.com/oauth2/v3/certs"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL")

    # Observability
    SENTRY_DSN: str = ""  # Optional: Sentry for error tracking
    LOG_LEVEL: str = "INFO"

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # --- External Product API Configuration ---
    # RATE_LIMIT_PER_MINUTE: int = os.getenv("RATE_LIMIT_PER_MINUTE")
    FAILURE_THRESHOLD: int = os.getenv("FAILURE_THRESHOLD")
    RECOVERY_TIMEOUT: int = os.getenv("RECOVERY_TIMEOUT")
    REQUEST_TIMEOUT: int = os.getenv("REQUEST_TIMEOUT")

    # --- Email Configuration ---
    EMAILS_FROM_EMAIL: str = os.getenv("EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: str = os.getenv("EMAILS_FROM_NAME")
    SMTP_HOST: str = os.getenv("SMTP_HOST")
    SMTP_PORT: int = os.getenv("SMTP_PORT")

    # Feature Flags
    ENABLE_REGISTRATION: bool = True
    ENABLE_PASSWORD_AUTH: bool = False  # OAuth-only for this implementation
    REQUIRE_EMAIL_VERIFICATION: bool = False

    # Admin
    ADMIN_EMAIL: str = "admin@yourapp.com"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Validate critical settings
        if self.ENVIRONMENT == "production":
            assert self.DEBUG is False, "DEBUG must be False in production"
            assert self.JWT_SECRET_KEY != secrets.token_urlsafe(32), "Must set JWT_SECRET_KEY in production"
            assert "localhost" not in self.GOOGLE_REDIRECT_URI, "Must use production redirect URI"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

settings = Settings()