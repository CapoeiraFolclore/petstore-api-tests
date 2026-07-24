"""Environment-based configuration loader."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import yaml
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_ENV = "dev"


@dataclass(frozen=True)
class ApiConfig:
    """Runtime configuration for API test execution."""

    environment: str
    base_url: str
    timeout: float
    verify_ssl: bool = True
    default_headers: Mapping[str, str] = field(default_factory=dict)
    auth: Mapping[str, str] = field(default_factory=dict)

    @property
    def base_url_normalized(self) -> str:
        return self.base_url.rstrip("/")


def _load_yaml(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration file must contain a mapping: {path}")
    return data


def _resolve_env_name() -> str:
    load_dotenv(PROJECT_ROOT / ".env")
    return os.getenv("API_ENV", DEFAULT_ENV).strip().lower()


def load_config(
    environment: Optional[str] = None,
    config_dir: Optional[Path] = None,
) -> ApiConfig:
    """Load configuration for the requested environment."""
    env_name = (environment or _resolve_env_name()).strip().lower()
    directory = config_dir or CONFIG_DIR
    config_path = directory / f"{env_name}.yaml"

    if not config_path.is_file():
        available = sorted(p.stem for p in directory.glob("*.yaml"))
        raise FileNotFoundError(
            f"Unknown environment '{env_name}'. Available: {', '.join(available)}"
        )

    raw = _load_yaml(config_path)

    base_url = os.getenv("API_BASE_URL", raw.get("base_url", "")).strip()
    if not base_url:
        raise ValueError(f"'base_url' is required in {config_path}")

    timeout_raw = os.getenv("API_TIMEOUT", raw.get("timeout", 30))
    timeout = float(timeout_raw)

    verify_ssl = raw.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.lower() in {"1", "true", "yes", "on"}

    default_headers = dict(raw.get("default_headers") or {})
    auth = dict(raw.get("auth") or {})

    return ApiConfig(
        environment=env_name,
        base_url=base_url,
        timeout=timeout,
        verify_ssl=verify_ssl,
        default_headers=default_headers,
        auth=auth,
    )
