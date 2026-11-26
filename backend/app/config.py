"""Environment-driven settings for ANDHAK EDR backend."""

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    edr_env: str = Field(default="development", alias="ANDHAK_EDR_ENV")
    host: str = Field(default="127.0.0.1", alias="ANDHAK_EDR_HOST")
    port: int = Field(default=8010, alias="ANDHAK_EDR_PORT")
    demo_mode: bool = Field(default=False, alias="ANDHAK_DEMO_MODE")

    data_dir: Path = Field(
        default_factory=lambda: _repo_root() / ".local-data",
        alias="ANDHAK_EDR_DATA_DIR",
    )
    db_path: Path | None = Field(default=None, alias="ANDHAK_EDR_DB_PATH")
    db_url: str | None = Field(default=None, alias="ANDHAK_EDR_DB_URL")

    jwt_secret: str = Field(
        default_factory=lambda: secrets.token_urlsafe(48),
        alias="ANDHAK_EDR_JWT_SECRET",
    )
    jwt_expire_minutes: int = Field(default=480, alias="ANDHAK_EDR_JWT_EXPIRE_MINUTES")
    bootstrap_token: str | None = Field(
        default=None,
        alias="ANDHAK_EDR_ENROLLMENT_BOOTSTRAP_TOKEN",
    )
    bootstrap_admin_username: str | None = Field(
        default=None,
        alias="ANDHAK_EDR_BOOTSTRAP_ADMIN_USER",
    )
    bootstrap_admin_password: str | None = Field(
        default=None,
        alias="ANDHAK_EDR_BOOTSTRAP_ADMIN_PASSWORD",
    )
    quarantine_vault_dir: Path | None = Field(
        default=None,
        alias="ANDHAK_EDR_QUARANTINE_DIR",
    )

    max_batch_events: int = 500
    retention_telemetry_days: int = Field(default=30, alias="ANDHAK_RETENTION_TELEMETRY_DAYS")
    retention_alerts_days: int = Field(default=90, alias="ANDHAK_RETENTION_ALERTS_DAYS")
    retention_incidents_days: int = Field(default=180, alias="ANDHAK_RETENTION_INCIDENTS_DAYS")
    retention_audit_days: int = Field(default=365, alias="ANDHAK_RETENTION_AUDIT_DAYS")

    # Stage 03 Threat Intelligence Policy Gates (external lookups strictly opt-in)
    intel_external_enabled: bool = Field(default=False, alias="ANDHAK_INTEL_EXTERNAL_ENABLED")
    intel_allow_hash_only: bool = Field(default=True, alias="ANDHAK_INTEL_ALLOW_HASH_ONLY")
    intel_allow_file_upload: bool = Field(default=False, alias="ANDHAK_INTEL_ALLOW_FILE_UPLOAD")
    malwarebazaar_auth_key: str | None = Field(default=None, alias="MALWAREBAZAAR_AUTH_KEY")
    abuseipdb_api_key: str | None = Field(default=None, alias="ABUSEIPDB_API_KEY")
    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    ember_model_path: Path | None = Field(default=None, alias="ANDHAK_EMBER_MODEL_PATH")

    @property
    def resolved_db_path(self) -> Path:
        if self.db_path is not None:
            return Path(self.db_path).expanduser().resolve()
        if self.db_url and self.db_url.startswith("sqlite"):
            raw = self.db_url.split("///", 1)[-1]
            p = Path(raw)
            if not p.is_absolute():
                p = (_repo_root() / p).resolve()
            return p
        return (self.data_dir / "andhak-edr.sqlite3").resolve()

    @property
    def schema_sql_path(self) -> Path:
        return _repo_root() / "docs" / "contracts" / "DATABASE_SCHEMA.sql"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
