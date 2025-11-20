"""Application configuration for OS Log Analyzer backend."""

import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class AppConfig:
    """Central configuration values for the Flask backend."""

    secret_key: str = os.environ.get("SECRET_KEY", "os-log-analyzer-secret-key")
    debug: bool = os.environ.get("FLASK_DEBUG", "True").lower() == "true"
    cors_origins: List[str] = field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5000",
            "http://127.0.0.1:5000",
        ]
    )
    log_update_interval: int = int(os.environ.get("LOG_UPDATE_INTERVAL", 3))
    max_logs_display: int = int(os.environ.get("MAX_LOGS_DISPLAY", 1000))
    upload_folder: str = os.environ.get("UPLOAD_FOLDER", "uploads")
    allowed_extensions: List[str] = field(
        default_factory=lambda: ["xlsx", "csv", "json", "log", "txt"]
    )
    database_path: str = os.environ.get("DATABASE_PATH", "security.db")
    quarantine_dir: str = os.environ.get("QUARANTINE_DIR", "quarantine")
    blacklist_enforcement_interval: int = int(
        os.environ.get("BLACKLIST_ENFORCEMENT_INTERVAL", 10)
    )
    metrics_poll_interval: int = int(os.environ.get("METRICS_POLL_INTERVAL", 5))


config = AppConfig()
