"""Typed application settings.

Loaded from (lowest to highest precedence): defaults, YAML file, ``AVERQON_*``
environment variables. Secrets are never given defaults: they must come from the
environment or a file with restrictive permissions.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.errors import ConfigError

DEFAULT_CONFIG_PATH = Path("/etc/averqon/averqon.yaml")


class DatabaseSettings(BaseModel):
    url: str = "sqlite:///./averqon-dev.db"
    echo: bool = False

    @field_validator("url")
    @classmethod
    def _scheme(cls, v: str) -> str:
        if not v.startswith(("sqlite:", "postgresql:", "postgresql+psycopg:")):
            raise ValueError("database url must be sqlite or postgresql")
        return v


class FirewallSettings(BaseModel):
    backend: Literal["auto", "nftables", "iptables"] = "auto"
    table_name: str = Field(default="averqon", pattern=r"^[a-z][a-z0-9_]{0,31}$")
    dry_run: bool = False
    default_input: Literal["accept", "drop"] = "drop"
    default_output: Literal["accept", "drop"] = "accept"
    default_forward: Literal["accept", "drop"] = "drop"
    admin_ips: list[str] = []
    syn_rate: str | None = None
    syn_burst: int = 400
    conn_limit_per_ip: int | None = None
    new_conn_rate_per_ip: str | None = None
    log_drops: bool = False
    blocklist_dir: Path = Path("/var/lib/averqon/blocklists")
    threat_feeds: dict[str, str] = {}  # name -> https URL
    blocklist_refresh_hours: int = Field(default=12, ge=1)
    geo_block_countries: list[str] = []
    geo_zone_dir: Path = Path("/var/lib/averqon/geo")
    backup_dir: Path = Path("/var/lib/averqon/backups")
    management_ports: list[int] = [22]
    rollback_timeout_seconds: int = Field(default=60, ge=10, le=600)

    @field_validator("management_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v):
            raise ValueError("port out of range")
        return v


class IdsSettings(BaseModel):
    enabled: bool = True
    jails: list[dict[str, Any]] | None = None  # None -> built-in defaults (validated as JailConfig)
    autoban: bool = True
    autoban_min_severity: Literal["low", "medium", "high", "critical"] = "medium"
    ignore_networks: list[str] = []
    escalation_multiplier: int = Field(default=2, ge=1, le=10)
    max_bantime: int = Field(default=30 * 86400, ge=60)
    permanent_after: int = Field(default=0, ge=0, description="offences before permanent ban; 0 = never")
    escalation_window: int = Field(default=30 * 86400, ge=3600)
    portscan_enabled: bool = True
    portscan_ports: int = Field(default=15, ge=3)
    portscan_window: int = Field(default=60, ge=5)
    portscan_bantime: int = Field(default=21600, ge=60)
    kernel_log_path: str | None = None  # None -> journalctl -k


class TelegramSettings(BaseModel):
    enabled: bool = False
    bot_token: SecretStr | None = None
    chat_id: str = ""
    api_base: str = "https://api.telegram.org"


class EmailSettings(BaseModel):
    enabled: bool = False
    host: str = "localhost"
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str = ""
    password: SecretStr | None = None
    from_addr: str = ""
    to_addrs: list[str] = []


class WebhookSettings(BaseModel):
    enabled: bool = False
    url: str = ""
    secret: SecretStr | None = None  # HMAC-SHA256 signing key (header X-Averqon-Signature)
    allow_private: bool = False  # SSRF guard: refuse loopback/private targets unless explicitly allowed


class NotificationSettings(BaseModel):
    min_severity: Literal["low", "medium", "high", "critical"] = "high"
    dedupe_seconds: int = Field(default=300, ge=0)
    telegram: TelegramSettings = TelegramSettings()
    email: EmailSettings = EmailSettings()
    webhook: WebhookSettings = WebhookSettings()
    cpu_alert_percent: int = Field(default=90, ge=1, le=100)
    memory_alert_percent: int = Field(default=90, ge=1, le=100)
    disk_alert_percent: int = Field(default=90, ge=1, le=100)
    alert_cooldown_seconds: int = Field(default=1800, ge=60)


class ApiSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8443, ge=1, le=65535)
    cors_origins: list[str] = []
    rate_limit_per_minute: int = Field(default=120, ge=1)
    login_rate_per_minute: int = Field(default=10, ge=1)
    write_rate_per_minute: int = Field(default=30, ge=1)
    token_ttl_minutes: int = Field(default=30, ge=1, le=1440)
    max_body_bytes: int = Field(default=65536, ge=1024)
    max_failed_logins: int = Field(default=5, ge=1)
    lockout_minutes: int = Field(default=15, ge=1)
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    executor_socket: str | None = None  # None -> in-process facade (development only)
    allowed_uids: list[int] = []  # uids allowed to talk to the executor


class Settings(BaseSettings):
    """Root settings object."""

    model_config = SettingsConfigDict(env_prefix="AVERQON_", env_nested_delimiter="__")

    environment: Literal["development", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = False
    data_dir: Path = Path("/var/lib/averqon")
    secret_key: SecretStr | None = None
    database: DatabaseSettings = DatabaseSettings()
    firewall: FirewallSettings = FirewallSettings()
    api: ApiSettings = ApiSettings()
    ids: IdsSettings = IdsSettings()
    notifications: NotificationSettings = NotificationSettings()

    def require_secret(self) -> str:
        """Return the signing secret or fail; production refuses short secrets."""
        if self.secret_key is None:
            raise ConfigError("AVERQON_SECRET_KEY is not set")
        value = self.secret_key.get_secret_value()
        if self.environment == "production" and len(value) < 32:
            raise ConfigError("secret_key must be at least 32 characters in production")
        return value


def check_file_permissions(path: Path) -> None:
    """Reject config files readable by group/other (they may hold secrets)."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{path} has insecure permissions {oct(mode)}; require 0600 (no group/other access)")


def load_settings(path: Path | None = None, *, enforce_permissions: bool = True) -> Settings:
    """Load settings from YAML (if present) overlaid with environment variables."""
    data: dict[str, Any] = {}
    if path is None and DEFAULT_CONFIG_PATH.exists():
        path = DEFAULT_CONFIG_PATH
    if path is not None:
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        if enforce_permissions and os.name == "posix":
            check_file_permissions(path)
        try:
            loaded = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigError("config root must be a mapping")
        data = loaded or {}
    try:
        # Environment variables override file values.
        env_overrides = Settings().model_dump(exclude_unset=True)
        merged = _deep_merge(data, env_overrides)
        return Settings.model_validate(merged)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration: {exc}") from exc


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, val in over.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out
