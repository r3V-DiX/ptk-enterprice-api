from pydantic_settings import BaseSettings
from pydantic import field_validator
import json


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://enterprise:enterprise123@localhost:5434/ptk_enterprise"
    REDIS_URL: str = "redis://localhost:6381/0"

    SECRET_KEY: str = "dev-secret-key-change-in-production"
    ADMIN_SECRET_SCOPE: str = "admin"
    BOOTSTRAP_SECRET: str = ""

    S3_BUCKET: str = "ptk-enterprise-artifacts"
    S3_REGION: str = "ap-south-1"
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""

    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""

    CELERY_BROKER_URL: str = "redis://localhost:6381/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6381/1"

    SCAN_EXPIRE_MINUTES: int = 30
    MAX_CONCURRENT_SCANS_PER_CLIENT: int = 3
    DEFAULT_RATE_LIMIT_RPM: int = 60

    ENV: str = "development"
    PORT: int = 8002

    # CORS — client-facing API origins
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    # Admin portal origins (kept separate so they never bleed into client API)
    ADMIN_PORTAL_ORIGINS: list[str] = ["http://localhost:3001"]

    # Resend — transactional email for admin OTP
    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = "admin@pentoolkit.com"

    # Admin portal — comma-separated list of emails allowed to request OTP
    ADMIN_EMAILS: str = ""
    # Session token TTL for admin portal (seconds)
    ADMIN_SESSION_TTL: int = 86400  # 24 hours
    # OTP code TTL (seconds)
    ADMIN_OTP_TTL: int = 600  # 10 minutes

    @field_validator("CORS_ORIGINS", "ADMIN_PORTAL_ORIGINS", mode="before")
    @classmethod
    def parse_json_list(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                # Support plain comma-separated fallback: "http://a.com,http://b.com"
                return [x.strip() for x in v.split(",") if x.strip()]
        return v

    def get_admin_emails(self) -> list[str]:
        """Return normalised list of allowed admin emails."""
        if not self.ADMIN_EMAILS:
            return []
        return [e.strip().lower() for e in self.ADMIN_EMAILS.split(",") if e.strip()]

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
