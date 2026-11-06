"""AgentGuard Configuration Module.

Provides filesystem paths and settings using the Python standard library.
"""
import os
from dataclasses import dataclass
from pathlib import Path

# Project root directory: C:\Users\nunna\Desktop\GURDAI1
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Default backend SQLite database path
DEFAULT_DATA_DIR = PROJECT_ROOT / "backend" / "data"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "crm.db"


@dataclass(frozen=True)
class AuthFailureSettings:
    max_failures: int = 20
    window_seconds: int = 60
    max_client_buckets: int = 4096
    retention_events: int = 10000


def _bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}") from None
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def get_auth_failure_settings() -> AuthFailureSettings:
    """Return bounded auth-abuse controls; invalid deployment settings fail startup."""
    return AuthFailureSettings(
        max_failures=_bounded_env_int(
            "AGENTGUARD_AUTH_FAILURE_LIMIT", 20, minimum=1, maximum=100
        ),
        window_seconds=_bounded_env_int(
            "AGENTGUARD_AUTH_FAILURE_WINDOW_SECONDS", 60, minimum=1, maximum=3600
        ),
        max_client_buckets=_bounded_env_int(
            "AGENTGUARD_AUTH_FAILURE_MAX_CLIENTS", 4096, minimum=1, maximum=8192
        ),
        retention_events=_bounded_env_int(
            "AGENTGUARD_AUTH_FAILURE_RETENTION", 10000, minimum=1, maximum=100000
        ),
    )


def get_db_path(custom_path: str | Path | None = None) -> Path:
    """Resolve and return database path, ensuring parent directory exists.
    
    Priority:
    1. Explicit custom_path argument.
    2. AGENTGUARD_DB_PATH environment variable.
    3. Default path at backend/data/crm.db.
    """
    if custom_path is not None:
        p = Path(custom_path)
    else:
        env_val = os.getenv("AGENTGUARD_DB_PATH")
        p = Path(env_val) if env_val else DEFAULT_DB_PATH
    
    p.parent.mkdir(parents=True, exist_ok=True)
    return p
