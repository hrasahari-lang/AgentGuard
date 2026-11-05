"""AgentGuard Database Layer.

Manages SQLite database initialization, table creation, repeatable
synthetic customer seeding, and invocation counter initialization.
"""
import sqlite3
from pathlib import Path
from typing import List, Dict, Any

from backend.app.config import get_db_path

# Table schemas as required by Milestone 1 specification
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_agent_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_invocation_counter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_name TEXT UNIQUE NOT NULL,
    total_invocations INTEGER NOT NULL DEFAULT 0,
    successful_invocations INTEGER NOT NULL DEFAULT 0
);
"""

# Realistic but entirely synthetic customer records using RFC 2606 reserved domains
SYNTHETIC_CUSTOMERS: List[Dict[str, str]] = [
    {
        "customer_id": "CUST-101",
        "name": "Acme Industrial Technologies",
        "email": "procurement@acme-industrial.example.com",
        "status": "active",
        "assigned_agent_id": "agent_sales_1",
    },
    {
        "customer_id": "CUST-102",
        "name": "BioPulse Medical Dynamics",
        "email": "ops@biopulse-dynamics.example.com",
        "status": "active",
        "assigned_agent_id": "agent_sales_1",
    },
    {
        "customer_id": "CUST-103",
        "name": "Cascade Mountain Logistics",
        "email": "dispatch@cascade-logistics.example.com",
        "status": "pending",
        "assigned_agent_id": "agent_sales_1",
    },
    {
        "customer_id": "CUST-104",
        "name": "Delta Horizon Retail Group",
        "email": "accounts@deltahorizon.example.com",
        "status": "active",
        "assigned_agent_id": "agent_sales_2",
    },
    {
        "customer_id": "CUST-105",
        "name": "Echo Star Data Analytics",
        "email": "contact@echostar-analytics.example.com",
        "status": "suspended",
        "assigned_agent_id": "agent_sales_2",
    },
    {
        "customer_id": "CUST-106",
        "name": "Fusion Grid Energy Networks",
        "email": "billing@fusiongrid-networks.example.com",
        "status": "active",
        "assigned_agent_id": "agent_sales_3",
    },
    {
        "customer_id": "CUST-107",
        "name": "Global Vertex Systems",
        "email": "admin@globalvertex.example.com",
        "status": "active",
        "assigned_agent_id": "agent_sales_3",
    },
]


def is_in_memory_db(target: str | Path) -> bool:
    """Check if target represents an SQLite in-memory database."""
    target_str = str(target).strip()
    return (
        target_str == ":memory:"
        or target_str.startswith("file::memory:")
        or "mode=memory" in target_str
    )


def get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Create and return a configured SQLite connection.
    
    Configures:
    - 15-second busy timeout for concurrent access safety.
    - Foreign keys enabled.
    - WAL (Write-Ahead Logging) journal mode for file-backed databases
      (skipped for in-memory databases).
    """
    target_path = get_db_path(db_path)
    target_str = str(target_path)
    conn = sqlite3.connect(target_str, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    if not is_in_memory_db(target_str):
        conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db(db_path: str | Path | None = None) -> Path:
    """Initialize SQLite database tables and seed synthetic records idempotently.
    
    Safe to execute repeatedly: existing records and counter rows are preserved
    without duplication. Explicitly closes connections for cross-platform file locking safety.
    """
    target_path = get_db_path(db_path)
    conn = get_connection(target_path)
    try:
        cursor = conn.cursor()
        cursor.executescript(SCHEMA_SQL)

        # Seed invocation counter row for 'crm' resource if not present
        cursor.execute(
            """
            INSERT OR IGNORE INTO resource_invocation_counter 
                (resource_name, total_invocations, successful_invocations)
            VALUES (?, 0, 0);
            """,
            ("crm",)
        )

        # Seed synthetic customer records idempotently
        for cust in SYNTHETIC_CUSTOMERS:
            cursor.execute(
                """
                INSERT OR IGNORE INTO customers 
                    (customer_id, name, email, status, assigned_agent_id)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    cust["customer_id"],
                    cust["name"],
                    cust["email"],
                    cust["status"],
                    cust["assigned_agent_id"],
                )
            )
        conn.commit()
    finally:
        conn.close()

    return target_path


if __name__ == "__main__":
    path = init_db()
    print(f"AgentGuard CRM database initialized successfully at: {path}")
