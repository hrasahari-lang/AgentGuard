"""AgentGuard CRM Repository.

Provides protected, modular access to the SQLite synthetic customer CRM database.
Enforces:
- Parameterized SQL for all queries (zero SQL injection).
- Agent-specific resource scoping inside database queries.
- Requirement for verified, trusted agent context from backend code.
- Strict input validation prior to repository execution.
- Persistent invocation counters tracking total entry vs. successful execution.
"""
import csv
from dataclasses import dataclass
import io
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Union

from backend.app.config import get_db_path
from backend.app.database import is_in_memory_db


@dataclass(frozen=True)
class TrustedAgentContext:
    """Trusted server-side representation of an authenticated calling agent.
    
    Security rule: Never trust agent identity or role supplied in tool arguments.
    This context is instantiated only by verified backend authentication.
    """
    agent_id: str
    is_admin: bool = False

    def __post_init__(self):
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise ValueError("TrustedAgentContext requires a non-empty string agent_id")
        if not isinstance(self.is_admin, bool):
            raise TypeError("is_admin must be a boolean")


# Counter tracking helpers that persist independently of transaction failures

def record_invocation(db_path: Union[str, Path], resource_name: str = "crm") -> None:
    """Record entry into a protected resource operation.
    
    Persists immediately in a dedicated connection to guarantee that the invocation
    counter increments even if the subsequent query encounters an error or failure.
    Uses a 15-second busy timeout and WAL mode for file-backed databases.
    """
    target = Path(db_path)
    target_str = str(target)
    conn = sqlite3.connect(target_str, timeout=15.0)
    try:
        if not is_in_memory_db(target_str):
            conn.execute("PRAGMA journal_mode = WAL;")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO resource_invocation_counter 
                (resource_name, total_invocations, successful_invocations)
            VALUES (?, 1, 0)
            ON CONFLICT(resource_name) DO UPDATE 
            SET total_invocations = total_invocations + 1;
            """,
            (resource_name,)
        )
        conn.commit()
    finally:
        conn.close()


def record_success(db_path: Union[str, Path], resource_name: str = "crm") -> None:
    """Record successful completion of a protected resource operation."""
    target = Path(db_path)
    conn = sqlite3.connect(str(target), timeout=15.0)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE resource_invocation_counter
            SET successful_invocations = successful_invocations + 1
            WHERE resource_name = ?;
            """,
            (resource_name,)
        )
        conn.commit()
    finally:
        conn.close()


def get_invocation_counts(db_path: Union[str, Path], resource_name: str = "crm") -> Dict[str, Any]:
    """Retrieve current total invocations and successful invocations for a resource."""
    target = Path(db_path)
    conn = sqlite3.connect(str(target), timeout=15.0)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, resource_name, total_invocations, successful_invocations
            FROM resource_invocation_counter
            WHERE resource_name = ?;
            """,
            (resource_name,)
        )
        row = cursor.fetchone()
        if row:
            return {
                "id": row["id"],
                "resource_name": row["resource_name"],
                "total_invocations": row["total_invocations"],
                "successful_invocations": row["successful_invocations"],
            }
        return {
            "id": None,
            "resource_name": resource_name,
            "total_invocations": 0,
            "successful_invocations": 0,
        }
    finally:
        conn.close()


def get_total_invocations(db_path: Union[str, Path], resource_name: str = "crm") -> int:
    """Convenience helper to read total repository invocations."""
    return get_invocation_counts(db_path, resource_name)["total_invocations"]


class CrmRepository:
    """Repository managing protected synthetic CRM operations with server-side scoping."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = get_db_path(db_path)

    def _get_connection(self) -> sqlite3.Connection:
        target_str = str(self.db_path)
        conn = sqlite3.connect(target_str, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if not is_in_memory_db(target_str):
            conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def get_customer_by_id(
        self,
        customer_id: str,
        agent_context: TrustedAgentContext
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single customer record by ID, scoped to the calling agent.
        
        Security Invariants:
        - Rejects invalid arguments before repository invocation (counter does not increment).
        - Enforces resource scope inside the parameterized SQL query.
        - Increments invocation counter immediately upon entering repository execution.
        """
        # Pre-validation (rejected before entering protected repository operations)
        if not isinstance(agent_context, TrustedAgentContext):
            raise TypeError("agent_context must be a valid TrustedAgentContext instance")
        if not isinstance(customer_id, str) or not customer_id.strip():
            raise ValueError("customer_id must be a non-empty string")

        # Record entry into protected resource operation
        record_invocation(self.db_path, "crm")

        clean_id = customer_id.strip()
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if agent_context.is_admin:
                cursor.execute(
                    """
                    SELECT customer_id, name, email, status, assigned_agent_id
                    FROM customers
                    WHERE customer_id = ?;
                    """,
                    (clean_id,)
                )
            else:
                cursor.execute(
                    """
                    SELECT customer_id, name, email, status, assigned_agent_id
                    FROM customers
                    WHERE customer_id = ? AND assigned_agent_id = ?;
                    """,
                    (clean_id, agent_context.agent_id)
                )
            row = cursor.fetchone()
        finally:
            conn.close()

        # Record success only after database operation completes without error
        record_success(self.db_path, "crm")

        if row is None:
            return None
        return dict(row)

    def search_customer_records(
        self,
        query: str,
        agent_context: TrustedAgentContext,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search synthetic customer records by name, email, or ID, scoped to the agent.
        
        Security Invariants:
        - Validates limit (1 <= limit <= 100) and query before repository invocation.
        - Parameterized SQL prevents injection.
        - Resource scope enforced in query (WHERE ... AND assigned_agent_id = ?).
        - SQL LIKE Wildcard Semantics:
          Wildcard characters ('%' and '_') in the query string are matched as standard
          SQL LIKE pattern characters by design. This allows substring matching (e.g.,
          partial domains or prefix searches). Because scoping is enforced at the SQL
          query level via `AND assigned_agent_id = ?`, wildcards can never match or expose
          records belonging to other agents.
        """
        # Pre-validation
        if not isinstance(agent_context, TrustedAgentContext):
            raise TypeError("agent_context must be a valid TrustedAgentContext instance")
        if not isinstance(query, str):
            raise ValueError("query must be a string")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer")
        if limit < 1 or limit > 100:
            raise ValueError("limit must be an integer between 1 and 100")

        # Record entry into protected resource operation
        record_invocation(self.db_path, "crm")

        like_term = f"%{query.strip()}%"
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if agent_context.is_admin:
                cursor.execute(
                    """
                    SELECT customer_id, name, email, status, assigned_agent_id
                    FROM customers
                    WHERE (name LIKE ? OR email LIKE ? OR customer_id LIKE ?)
                    ORDER BY customer_id ASC
                    LIMIT ?;
                    """,
                    (like_term, like_term, like_term, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT customer_id, name, email, status, assigned_agent_id
                    FROM customers
                    WHERE (name LIKE ? OR email LIKE ? OR customer_id LIKE ?)
                      AND assigned_agent_id = ?
                    ORDER BY customer_id ASC
                    LIMIT ?;
                    """,
                    (like_term, like_term, like_term, agent_context.agent_id, limit)
                )
            rows = cursor.fetchall()
        finally:
            conn.close()

        record_success(self.db_path, "crm")
        return [dict(r) for r in rows]

    def export_customer_records(
        self,
        agent_context: TrustedAgentContext,
        format: str = "json",
        limit: int = 100,
    ) -> str:
        """Export customer records in JSON or CSV format, scoped to the agent.
        
        Note: This is a protected sensitive operation reserved for policy enforcement
        demonstration in subsequent milestones.
        """
        # Pre-validation
        if not isinstance(agent_context, TrustedAgentContext):
            raise TypeError("agent_context must be a valid TrustedAgentContext instance")
        if not isinstance(format, str) or format.lower() not in ("json", "csv"):
            raise ValueError("format must be either 'json' or 'csv'")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be an integer between 1 and 1000")

        # Record entry into protected resource operation
        record_invocation(self.db_path, "crm")

        fmt = format.lower()
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if agent_context.is_admin:
                cursor.execute(
                    """
                    SELECT customer_id, name, email, status, assigned_agent_id
                    FROM customers
                    ORDER BY customer_id ASC
                    LIMIT ?;
                    """,
                    (limit,)
                )
            else:
                cursor.execute(
                    """
                    SELECT customer_id, name, email, status, assigned_agent_id
                    FROM customers
                    WHERE assigned_agent_id = ?
                    ORDER BY customer_id ASC
                    LIMIT ?;
                    """,
                    (agent_context.agent_id, limit)
                )
            rows = cursor.fetchall()
        finally:
            conn.close()

        records = [dict(r) for r in rows]

        if fmt == "json":
            result = json.dumps(records, indent=2)
        else:
            output = io.StringIO()
            fieldnames = ["customer_id", "name", "email", "status", "assigned_agent_id"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for rec in records:
                writer.writerow(rec)
            result = output.getvalue()

        record_success(self.db_path, "crm")
        return result
