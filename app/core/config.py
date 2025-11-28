import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Manages all application settings. Loads variables from environment and a .env file.
    """

    # --- Application Metadata ---
    ENVIRONMENT: str = os.getenv("hml")
    DEBUG: str = os.getenv("DEBUG")
    PROJECT_NAME: str = os.getenv("PROJECT_NAME")
    VERSION: str = os.getenv("VERSION")
    API_V1_STR: str = f"/api/{VERSION}"

    # --- Security & JWT Configuration ---
    # To generate a good secret key: openssl rand -hex 32
    API_KEY: str = os.getenv("API_KEY")
    SECRET_KEY: str = os.getenv("SECRET_KEY")
    ALGORITHM: str = os.getenv("ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
    REFRESH_TOKEN_EXPIRE_DAYS: int = os.getenv("REFRESH_TOKEN_EXPIRE_DAYS")


    FRONTEND_URL: str = os.getenv("FRONTEND_URL")
    # Prefer True in production for certificate validation
    HTTPX_VERIFY_SSL: bool = os.getenv("HTTPX_VERIFY_SSL", True)
    HTTPX_MAX_KEEPALIVE: str = os.getenv("HTTPX_MAX_KEEPALIVE", 20)
    HTTPX_MAX_CONNECTIONS: str = os.getenv("HTTPX_MAX_CONNECTIONS", 100)
    HTTPX_KEEPALIVE_EXPIRY: str = os.getenv("HTTPX_KEEPALIVE_EXPIRY", 60)

    # Google OAuth
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI: str = os.getenv(f"{FRONTEND_URL}/auth/callback/google")
    GOOGLE_TOKEN_URL: str = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL: str = "https://www.googleapis.com/oauth2/v3/userinfo"
    GOOGLE_JWKS_URL: str = "https://www.googleapis.com/oauth2/v3/certs"

    # Microsoft config <--- NEW
    MICROSOFT_CLIENT_ID: str = os.getenv("MICROSOFT_CLIENT_ID")
    MICROSOFT_CLIENT_SECRET: str = os.getenv("MICROSOFT_CLIENT_SECRET")
    MICROSOFT_REDIRECT_URI: str = os.getenv("MICROSOFT_REDIRECT_URI")

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL")
    
    # --- External Product API Configuration ---
    RATE_LIMIT_PER_MINUTE: int = os.getenv("RATE_LIMIT_PER_MINUTE")
    FAILURE_THRESHOLD: int = os.getenv("FAILURE_THRESHOLD")
    RECOVERY_TIMEOUT: int = os.getenv("RECOVERY_TIMEOUT")
    REQUEST_TIMEOUT: int = os.getenv("REQUEST_TIMEOUT")

    # --- Email Configuration ---
    EMAILS_FROM_EMAIL: str = os.getenv("EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: str = os.getenv("EMAILS_FROM_NAME")
    SMTP_HOST: str = os.getenv("SMTP_HOST")
    SMTP_PORT: int = os.getenv("SMTP_PORT")

    class Config:
        case_sensitive = True
        from_attributes = True
        env_file = "../.env"

settings = Settings()