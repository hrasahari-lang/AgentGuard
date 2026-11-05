"""Append-first SQLite audit records for governed MCP tool requests."""
from __future__ import annotations

import sqlite3
import time
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
                columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_events)")}
                for column, definition in (
                    ("request_id", "TEXT"),
                    ("mcp_request_id", "TEXT"),
                    ("request_hash", "TEXT"),
                    ("execution_started_at", "REAL"),
                    ("execution_completed_at", "REAL"),
                ):
                    if column not in columns:
                        conn.execute(f"ALTER TABLE audit_events ADD COLUMN {column} {definition}")
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS authentication_failure_events (
                        event_id TEXT PRIMARY KEY,
                        failure_type TEXT NOT NULL CHECK (failure_type IN (
                            'MISSING_CREDENTIAL', 'MALFORMED_BEARER', 'INVALID_TOKEN',
                            'REVOKED_CREDENTIAL', 'DUPLICATE_AUTHORIZATION',
                            'CREDENTIAL_REGISTRY_FAILURE'
                        )),
                        timestamp REAL NOT NULL
                    )"""
                )
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS idempotency_requests (
                        agent_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        request_hash TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (agent_id, request_id)
                    )"""
                )

    def record_decision(
        self,
        decision: PolicyDecision,
        execution_status: str,
        request_id: str | None = None,
        request_hash: str | None = None,
        mcp_request_id: str | None = None,
    ) -> str:
        """Persist authorization before a protected side effect; never store request values."""
        event_id = uuid.uuid4().hex
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                conn.execute(
                    """INSERT INTO audit_events
                       (event_id, agent_id, tool_name, action, resource, decision,
                        policy_id, execution_status, error_type, timestamp,
                        request_id, request_hash, mcp_request_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)""",
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
                        request_id,
                        request_hash,
                        mcp_request_id,
                    ),
                )
        return event_id

    def claim_request(
        self, agent_id: str, request_id: str, request_hash: str, event_id: str
    ) -> tuple[bool, str | None, bool]:
        """Atomically reserve an authenticated request ID once per agent."""
        now = time.time()
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO idempotency_requests
                       (agent_id, request_id, request_hash, event_id, status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 'DECISION_RECORDED', ?, ?)""",
                    (agent_id, request_id, request_hash, event_id, now, now),
                )
                if cursor.rowcount == 1:
                    return True, None, True
                row = conn.execute(
                    "SELECT request_hash, status FROM idempotency_requests WHERE agent_id=? AND request_id=?",
                    (agent_id, request_id),
                ).fetchone()
                if row is None:
                    raise RuntimeError("idempotency reservation could not be read")
                return False, row[1], row[0] == request_hash

    def mark_execution_started(self, event_id: str, agent_id: str, request_id: str) -> None:
        now = time.time()
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                cursor = conn.execute(
                    """UPDATE audit_events SET execution_status='STARTED', execution_started_at=?
                       WHERE event_id=? AND execution_status='DECISION_RECORDED'""",
                    (now, event_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("execution could not be marked as started")
                cursor = conn.execute(
                    """UPDATE idempotency_requests SET status='STARTED', updated_at=?
                       WHERE agent_id=? AND request_id=? AND event_id=? AND status='DECISION_RECORDED'""",
                    (now, agent_id, request_id, event_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("idempotency request could not be marked as started")

    def mark_request_rejected(self, event_id: str, status: str) -> None:
        if status not in {"DUPLICATE_REQUEST", "REQUEST_ID_CONFLICT"}:
            raise ValueError("invalid request rejection status")
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                cursor = conn.execute(
                    "UPDATE audit_events SET execution_status=? WHERE event_id=? AND execution_status='DECISION_RECORDED'",
                    (status, event_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("duplicate request could not be audited")

    def record_authentication_failure(self, failure_type: str) -> None:
        allowed = {
            "MISSING_CREDENTIAL", "MALFORMED_BEARER", "INVALID_TOKEN",
            "REVOKED_CREDENTIAL", "DUPLICATE_AUTHORIZATION", "CREDENTIAL_REGISTRY_FAILURE",
        }
        if failure_type not in allowed:
            raise ValueError("invalid authentication failure category")
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                conn.execute(
                    "INSERT INTO authentication_failure_events(event_id, failure_type, timestamp) VALUES (?, ?, ?)",
                    (uuid.uuid4().hex, failure_type, time.time()),
                )

    def record_outcome(self, event_id: str, status: str, error_type: str | None = None) -> None:
        if status not in {"SUCCEEDED", "FAILED"}:
            raise ValueError("invalid execution status")
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                cursor = conn.execute(
                    "UPDATE audit_events SET execution_status=?, error_type=?, execution_completed_at=? WHERE event_id=? AND execution_status='STARTED'",
                    (status, error_type, time.time(), event_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("audit execution record was not updated")
                cursor = conn.execute(
                    """UPDATE idempotency_requests SET status=?, updated_at=?
                       WHERE event_id=? AND status='STARTED'""",
                    (status, time.time(), event_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("idempotency outcome record was not updated")

    def record_outcome_audit_failure(self, event_id: str) -> None:
        """Best-effort marker; a failed write leaves the request safely in STARTED state."""
        now = time.time()
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            with conn:
                cursor = conn.execute(
                    """UPDATE audit_events SET execution_status='OUTCOME_AUDIT_FAILED'
                       WHERE event_id=? AND execution_status='STARTED'""",
                    (event_id,),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("outcome audit failure could not be marked")
                cursor = conn.execute(
                    """UPDATE idempotency_requests SET status='OUTCOME_AUDIT_FAILED', updated_at=?
                       WHERE event_id=? AND status='STARTED'""",
                    (now, event_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("idempotency audit failure could not be marked")

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT event_id, agent_id, tool_name, action, resource, decision, policy_id,
                          execution_status, error_type, timestamp, request_id,
                          execution_started_at, execution_completed_at, mcp_request_id
                   FROM audit_events ORDER BY timestamp, rowid LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
