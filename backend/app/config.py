"""AgentGuard Configuration Module.

Provides filesystem paths and settings using the Python standard library.
"""
import os
from pathlib import Path

# Project root directory: C:\Users\nunna\Desktop\GURDAI1
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Default backend SQLite database path
DEFAULT_DATA_DIR = PROJECT_ROOT / "backend" / "data"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "crm.db"


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
