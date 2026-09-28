"""
SEC-AUDIT ENTERPRISE - Configuración Central del Sistema
Carga segura de variables de entorno mediante Pydantic Settings.
"""

import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    APP_NAME: str = os.getenv("APP_NAME", "SEC-AUDIT SERMIG Enterprise")
    APP_ENV: str = os.getenv("APP_ENV", "production")
    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", 8000))
    API_PREFIX: str = os.getenv("API_PREFIX", "/api/v1")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-insecure-secret-key-change-me")

    # Base de Datos
    DB_HOST: str = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT: int = int(os.getenv("DB_PORT", 5432))
    DB_NAME: str = os.getenv("DB_NAME", "sec_audit_db")
    DB_USER: str = os.getenv("DB_USER", "sec_audit_user")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    # Redis & Celery
    REDIS_HOST: str = os.getenv("REDIS_HOST", "127.0.0.1")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")

    # Azure CSPM
    AZURE_TENANT_ID: str = os.getenv("AZURE_TENANT_ID", "")
    AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
    AZURE_CLIENT_SECRET: str = os.getenv("AZURE_CLIENT_SECRET", "")
    AZURE_SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID", "")

    # OCI CSPM
    OCI_USER_OCID: str = os.getenv("OCI_USER_OCID", "")
    OCI_KEY_FINGERPRINT: str = os.getenv("OCI_KEY_FINGERPRINT", "")
    OCI_KEY_FILE_PATH: str = os.getenv("OCI_KEY_FILE_PATH", "")
    OCI_TENANCY_OCID: str = os.getenv("OCI_TENANCY_OCID", "")
    OCI_REGION: str = os.getenv("OCI_REGION", "sa-santiago-1")

    # Scans & Security Limits
    MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", 4))
    DEFAULT_SCAN_RATE_LIMIT: int = int(os.getenv("DEFAULT_SCAN_RATE_LIMIT", 50))
    REQUIRE_EXPLICIT_SCOPE_APPROVAL: bool = os.getenv("REQUIRE_EXPLICIT_SCOPE_APPROVAL", "true").lower() == "true"

settings = Settings()
