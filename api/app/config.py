from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    database_url: str = os.environ.get("DATABASE_URL", "postgresql://ipam:ipam@localhost:5432/ipam")
    bootstrap_api_key: str | None = os.environ.get("IPAM_BOOTSTRAP_API_KEY") or None
    seed_dir: Path = Path(os.environ.get("IPAM_SEED_DIR", str(APP_DIR.parents[1] / "seed")))
    migrations_dir: Path = Path(os.environ.get("IPAM_MIGRATIONS_DIR", str(APP_DIR.parent / "migrations")))
    web_dir: Path = Path(os.environ.get("IPAM_WEB_DIR", str(APP_DIR.parents[1] / "web")))
    expiry_sweep_seconds: int = int(os.environ.get("IPAM_EXPIRY_SWEEP_SECONDS", "60"))
    db_pool_max: int = int(os.environ.get("IPAM_DB_POOL_MAX", "20"))


settings = Settings()

API_PREFIX = "/api/v1"
ALL_SCOPES = ["read", "hosts:reserve", "hosts:write", "sites:deploy", "templates:write"]
LIVE_SITE_STATUSES = ("reserved", "allocated", "active", "decommissioning")
