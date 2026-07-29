from pydantic_settings import BaseSettings
from pydantic import field_validator
import json


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://enterprise:enterprise123@localhost:5434/ptk_enterprise"
    REDIS_URL: str = "redis://localhost:6381/0"

    SECRET_KEY: str = "dev-secret-key-change-in-production"
    ADMIN_SECRET_SCOPE: str = "admin"
    # Used only for bootstrapping the first admin key. Lock down in Phase 6.
    BOOTSTRAP_SECRET: str = ""

    S3_BUCKET: str = "ptk-enterprise-artifacts"
    S3_REGION: str = "us-east-1"
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
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return json.loads(v)
        return v

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
