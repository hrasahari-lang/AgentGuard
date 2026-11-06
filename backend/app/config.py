"""AgentGuard Configuration Module.

Provides filesystem paths and settings using the Python standard library.
"""
import os
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

# Project root directory: C:\Users\nunna\Desktop\GURDAI1
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Default backend SQLite database path
DEFAULT_DATA_DIR = PROJECT_ROOT / "backend" / "data"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "crm.db"
DEFAULT_CORS_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")
DEFAULT_MCP_ALLOWED_HOSTS = (
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
    "agentguard-api-g87x.onrender.com",
)


def get_cors_origins() -> list[str]:
    """Return exact canonical browser origins, defaulting to local Vite development."""
    raw = os.getenv("AGENTGUARD_CORS_ORIGINS")
    if raw is None:
        return list(DEFAULT_CORS_ORIGINS)
    if not raw.strip():
        raise ValueError("AGENTGUARD_CORS_ORIGINS must contain at least one exact origin")

    origins: list[str] = []
    for value in raw.split(","):
        if not value or value != value.strip() or value == "*":
            raise ValueError("AGENTGUARD_CORS_ORIGINS must contain exact origins, not wildcards")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise ValueError("AGENTGUARD_CORS_ORIGINS contains a malformed origin") from None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or "%" in parsed.netloc
        ):
            raise ValueError("AGENTGUARD_CORS_ORIGINS must contain scheme and host only")

        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower()
        if host.endswith("."):
            raise ValueError("AGENTGUARD_CORS_ORIGINS host must be canonical")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if not all(
                label
                and len(label) <= 63
                and label[0].isascii()
                and label[0].isalnum()
                and label[-1].isascii()
                and label[-1].isalnum()
                and all(char.isascii() and (char.isalnum() or char == "-") for char in label)
                for label in labels
            ):
                raise ValueError("AGENTGUARD_CORS_ORIGINS contains an invalid hostname") from None
            if all(label.isdigit() for label in labels):
                raise ValueError("AGENTGUARD_CORS_ORIGINS contains an ambiguous numeric hostname")
            local_host = host == "localhost"
            rendered_host = host
        else:
            local_host = address.is_loopback
            rendered_host = f"[{address.compressed}]" if address.version == 6 else address.compressed

        if scheme == "http" and not local_host:
            raise ValueError("Non-loopback AGENTGUARD_CORS_ORIGINS must use HTTPS")
        if port == (443 if scheme == "https" else 80):
            raise ValueError("AGENTGUARD_CORS_ORIGINS must omit the default port")
        canonical = f"{scheme}://{rendered_host}" + (f":{port}" if port is not None else "")
        if value != canonical:
            raise ValueError("AGENTGUARD_CORS_ORIGINS must use canonical origin spelling")
        if canonical in origins:
            raise ValueError("AGENTGUARD_CORS_ORIGINS must not contain duplicate origins")
        origins.append(canonical)
    return origins


def get_mcp_allowed_hosts() -> list[str]:
    """Return exact MCP Host header names plus loopback-only development patterns."""
    raw = os.getenv("AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS")
    if raw is None:
        remote_hosts = [DEFAULT_MCP_ALLOWED_HOSTS[-1]]
    else:
        if not raw.strip():
            raise ValueError("AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS must contain at least one hostname")
        remote_hosts = []
        for hostname in raw.split(","):
            if (
                hostname != hostname.strip()
                or hostname != hostname.lower()
                or len(hostname) > 253
                or hostname.endswith(".")
            ):
                raise ValueError("AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS must contain canonical hostnames")
            labels = hostname.split(".")
            if len(labels) < 2 or any(
                not label
                or len(label) > 63
                or not label[0].isascii()
                or not label[0].isalnum()
                or not label[-1].isascii()
                or not label[-1].isalnum()
                or any(not char.isascii() or not (char.isalnum() or char == "-") for char in label)
                for label in labels
            ) or all(label.isdigit() for label in labels):
                raise ValueError(
                    "AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS must contain exact DNS hostnames without schemes or ports"
                )
            if hostname in remote_hosts:
                raise ValueError("AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS must not contain duplicates")
            remote_hosts.append(hostname)
    return [*DEFAULT_MCP_ALLOWED_HOSTS[:-1], *remote_hosts]


@dataclass(frozen=True)
class AuthFailureSettings:
    max_failures: int = 20
    max_auth_requests: int = 300
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
        max_auth_requests=_bounded_env_int(
            "AGENTGUARD_AUTH_REQUEST_LIMIT", 300, minimum=1, maximum=10000
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
