"""Append-first SQLite audit records for governed MCP tool requests."""
from __future__ import annotations

import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from backend.app.config import get_db_path
from backend.app.policy_engine import PolicyDecision


class AuditStore:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = get_db_path(db_path)
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        action TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        policy_id TEXT,
                        execution_status TEXT NOT NULL,
                        error_type TEXT,
                        timestamp REAL NOT NULL
                    )"""
                )

    def record_decision(self, decision: PolicyDecision, execution_status: str) -> str:
        """Persist authorization before a protected side effect; never store request values."""
        event_id = uuid.uuid4().hex
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                conn.execute(
                    """INSERT INTO audit_events
                       (event_id, agent_id, tool_name, action, resource, decision,
                        policy_id, execution_status, error_type, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)""",
                    (
                        event_id,
                        decision.agent_id,
                        decision.tool_name,
                        decision.action,
                        decision.resource,
                        decision.outcome.value,
                        decision.policy_id,
                        execution_status,
                        decision.timestamp,
                    ),
                )
        return event_id

    def record_outcome(self, event_id: str, status: str, error_type: str | None = None) -> None:
        if status not in {"SUCCEEDED", "FAILED"}:
            raise ValueError("invalid execution status")
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                cursor = conn.execute(
                    "UPDATE audit_events SET execution_status=?, error_type=? WHERE event_id=? AND execution_status='STARTED'",
                    (status, error_type, event_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("audit execution record was not updated")

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY timestamp, rowid LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]
