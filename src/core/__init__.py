"""Core configuration module using pydantic-settings."""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = BASE_DIR / "config"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "PII-Shield"
    app_env: Environment = Environment.DEVELOPMENT
    app_debug: bool = False
    app_port: int = 8000
    app_host: str = "0.0.0.0"
    secret_key: str = "dev-secret-key-change-in-production"
    api_key_header: str = "X-API-Key"

    # Database
    database_url: str = "sqlite+aiosqlite:///./pii_shield.db"
    database_echo: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # ML Models
    ner_model_name: str = "dslim/bert-base-NER"
    transformer_model: str = "microsoft/deberta-v3-base"
    model_cache_dir: str = str(BASE_DIR / "model_cache")
    use_gpu: bool = False

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_ingest: str = "pii-ingest"
    kafka_topic_alerts: str = "pii-alerts"
    kafka_consumer_group: str = "pii-shield-group"

    # Alerting
    slack_webhook_url: str = ""
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_from: str = ""
    alert_email_to: str = ""
    webhook_alert_url: str = ""

    # Encryption
    encryption_key: str = ""
    data_retention_hours: int = 24

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Storage
    upload_dir: str = str(BASE_DIR / "uploads")
    report_dir: str = str(BASE_DIR / "reports")
    max_file_size_mb: int = 100

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            import json
            try:
                return json.loads(v)
            except (json.JSONDecodeError, TypeError):
                return [origin.strip() for origin in v.split(",")]
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == Environment.PRODUCTION


class AppConfig:
    """Full application config loaded from YAML + env."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._yaml_config: dict[str, Any] = {}
        self._load_yaml_config()

    def _load_yaml_config(self) -> None:
        yaml_path = CONFIG_DIR / "settings.yaml"
        if yaml_path.exists():
            with open(yaml_path) as f:
                self._yaml_config = yaml.safe_load(f) or {}

    def get(self, key: str, default: Any = None) -> Any:
        """Get nested config value using dot notation."""
        keys = key.split(".")
        value = self._yaml_config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    @property
    def detection_config(self) -> dict[str, Any]:
        return self._yaml_config.get("detection", {})

    @property
    def classification_config(self) -> dict[str, Any]:
        return self._yaml_config.get("classification", {})

    @property
    def compliance_config(self) -> dict[str, Any]:
        return self._yaml_config.get("compliance", {})

    @property
    def alerting_config(self) -> dict[str, Any]:
        return self._yaml_config.get("alerting", {})

    @property
    def masking_config(self) -> dict[str, Any]:
        return self._yaml_config.get("masking", {})

    @property
    def reporting_config(self) -> dict[str, Any]:
        return self._yaml_config.get("reporting", {})


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_app_config() -> AppConfig:
    return AppConfig()
