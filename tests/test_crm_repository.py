"""Automated Unit Tests for AgentGuard Milestone 1.

Tests SQLite initialization, synthetic data seeding, repository CRUD operations,
agent-specific query scoping, limit validation, SQL injection resistance,
and persistent invocation counter behavior (including failure persistence).
"""
import gc
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from backend.app.database import init_db, SYNTHETIC_CUSTOMERS
from backend.app.crm_repository import (
    CrmRepository,
    TrustedAgentContext,
    get_invocation_counts,
    get_total_invocations,
)
from tests.context_fixtures import authenticated_test_context


class TestCrmRepositoryMilestone1(unittest.TestCase):
    """Test suite covering all Milestone 1 requirements using isolated temporary databases."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_crm.db"
        init_db(self.db_path)
        self.repo = CrmRepository(self.db_path)
        self.agent_1 = authenticated_test_context("agent_sales_1")
        self.agent_2 = authenticated_test_context("agent_sales_2")
        self.agent_3 = authenticated_test_context("agent_sales_3")
        self.admin_agent = authenticated_test_context("admin_service", is_admin=True)

    def tearDown(self):
        # Allow Windows sqlite3 handles to release before removing temporary directory
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except PermissionError:
            # On Windows, brief file lock delay can occur; retry once after short pause
            time.sleep(0.05)
            gc.collect()
            try:
                self.temp_dir.cleanup()
            except Exception:
                pass

    # 1. Database initialization
    def test_database_initialization(self):
        """Verify database tables exist with required schemas."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cursor.fetchall()}
            self.assertIn("customers", tables)
            self.assertIn("resource_invocation_counter", tables)

            # Check customers columns
            cursor.execute("PRAGMA table_info(customers);")
            cust_cols = {row[1] for row in cursor.fetchall()}
            expected_cust_cols = {
                "customer_id", "name", "email", "status", "assigned_agent_id"
            }
            self.assertTrue(expected_cust_cols.issubset(cust_cols))

            # Check resource_invocation_counter columns
            cursor.execute("PRAGMA table_info(resource_invocation_counter);")
            counter_cols = {row[1] for row in cursor.fetchall()}
            expected_counter_cols = {
                "id", "resource_name", "total_invocations", "successful_invocations"
            }
            self.assertTrue(expected_counter_cols.issubset(counter_cols))
        finally:
            conn.close()

    # 2. Synthetic data seeding
    def test_synthetic_data_seeding(self):
        """Verify synthetic data has >= 6 records, safe domains, and idempotent seeding."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM customers;")
            count = cursor.fetchone()[0]
            self.assertGreaterEqual(count, 6)

            # Check synthetic email domain invariant
            cursor.execute("SELECT email FROM customers;")
            for (email,) in cursor.fetchall():
                self.assertTrue(
                    email.endswith(".example.com"),
                    f"Email {email} does not use RFC 2606 reserved example domain"
                )
        finally:
            conn.close()

        # Re-run init_db to test idempotency
        init_db(self.db_path)
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM customers;")
            re_count = cursor.fetchone()[0]
            self.assertEqual(count, re_count, "Database re-seeding duplicated customer rows")
        finally:
            conn.close()

        # Initial invocation counts should remain 0
        counts = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(counts["total_invocations"], 0)
        self.assertEqual(counts["successful_invocations"], 0)

    # 3. Successful customer lookup
    def test_successful_customer_lookup(self):
        """Verify customer retrieval returns accurate dictionary record."""
        cust = self.repo.get_customer_by_id("CUST-101", self.agent_1)
        self.assertIsNotNone(cust)
        self.assertEqual(cust["customer_id"], "CUST-101")
        self.assertEqual(cust["name"], "Acme Industrial Technologies")
        self.assertEqual(cust["status"], "active")
        self.assertEqual(cust["assigned_agent_id"], "agent_sales_1")

    # 4. Customer search
    def test_customer_search(self):
        """Verify search matches substring across name, email, and ID."""
        # By partial name
        results = self.repo.search_customer_records(
            query="BioPulse", limit=10, agent_context=self.agent_1
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["customer_id"], "CUST-102")

        # By partial ID
        id_results = self.repo.search_customer_records(
            query="CUST-103", limit=10, agent_context=self.agent_1
        )
        self.assertEqual(len(id_results), 1)
        self.assertEqual(id_results[0]["name"], "Cascade Mountain Logistics")

        # Multiple matches for agent 1
        all_agent_1 = self.repo.search_customer_records(
            query="example.com", limit=10, agent_context=self.agent_1
        )
        self.assertEqual(len(all_agent_1), 3)

        # SQL LIKE wildcard '%' and '_' semantics scoped to agent
        wildcard_results = self.repo.search_customer_records(
            query="%", limit=10, agent_context=self.agent_1
        )
        self.assertEqual(len(wildcard_results), 3)
        for r in wildcard_results:
            self.assertEqual(r["assigned_agent_id"], "agent_sales_1")

    # 5. Agent-specific record access (scoping)
    def test_agent_specific_record_access(self):
        """Verify agents can only access their assigned customers, while admin has broad scope."""
        # agent_1 cannot view CUST-104 (assigned to agent_2)
        cust_cross = self.repo.get_customer_by_id("CUST-104", self.agent_1)
        self.assertIsNone(cust_cross, "Agent accessed a customer assigned to another agent!")

        # agent_1 search cannot return agent_2's customer
        search_cross = self.repo.search_customer_records(
            query="Delta Horizon", limit=10, agent_context=self.agent_1
        )
        self.assertEqual(len(search_cross), 0)

        # agent_1 export only exports agent_1's records
        export_1 = self.repo.export_customer_records(
            format="json", limit=100, agent_context=self.agent_1
        )
        records_1 = json.loads(export_1)
        for rec in records_1:
            self.assertEqual(rec["assigned_agent_id"], "agent_sales_1")

        # admin_agent can view any record
        admin_view = self.repo.get_customer_by_id("CUST-104", self.admin_agent)
        self.assertIsNotNone(admin_view)
        self.assertEqual(admin_view["assigned_agent_id"], "agent_sales_2")

    # 6. Record limits
    def test_record_limits(self):
        """Verify record limit enforcement and validation."""
        # Valid limit restricts results
        results = self.repo.search_customer_records(
            query="example.com", limit=2, agent_context=self.admin_agent
        )
        self.assertEqual(len(results), 2)

        # Limit <= 0 rejected
        with self.assertRaises(ValueError):
            self.repo.search_customer_records(
                query="test", limit=0, agent_context=self.agent_1
            )
        with self.assertRaises(ValueError):
            self.repo.search_customer_records(
                query="test", limit=-5, agent_context=self.agent_1
            )

        # Limit > 100 rejected in search
        with self.assertRaises(ValueError):
            self.repo.search_customer_records(
                query="test", limit=101, agent_context=self.agent_1
            )

        # Invalid types rejected (bool, str)
        with self.assertRaises(ValueError):
            self.repo.search_customer_records(
                query="test", limit=True, agent_context=self.agent_1
            )
        with self.assertRaises(ValueError):
            self.repo.search_customer_records(
                query="test", limit="10", agent_context=self.agent_1
            )

    # 7. SQL injection resistance
    def test_sql_injection_resistance(self):
        """Verify parameterized queries prevent SQL injection payloads."""
        # Malicious customer_id lookup
        malicious_id = "CUST-101' OR '1'='1"
        res = self.repo.get_customer_by_id(malicious_id, self.agent_1)
        self.assertIsNone(res, "SQL injection in customer_id returned unescaped record")

        # Malicious drop table attempt
        drop_attempt = "'; DROP TABLE customers; --"
        res_drop = self.repo.get_customer_by_id(drop_attempt, self.agent_1)
        self.assertIsNone(res_drop)

        # Verify table still exists
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM customers;")
            self.assertGreater(cursor.fetchone()[0], 0)
        finally:
            conn.close()

        # Malicious UNION SELECT in search query
        malicious_search = "' UNION SELECT id, resource_name, total_invocations, 'active', 'agent_sales_1' FROM resource_invocation_counter --"
        search_res = self.repo.search_customer_records(
            query=malicious_search, limit=10, agent_context=self.agent_1
        )
        self.assertEqual(len(search_res), 0)

    # 8. Invocation counter increments
    def test_invocation_counter_increments(self):
        """Verify invocation counter increments on repository entry and successful execution."""
        initial_counts = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(initial_counts["total_invocations"], 0)
        self.assertEqual(initial_counts["successful_invocations"], 0)

        # Operation 1: lookup
        self.repo.get_customer_by_id("CUST-101", self.agent_1)
        c1 = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(c1["total_invocations"], 1)
        self.assertEqual(c1["successful_invocations"], 1)

        # Operation 2: search
        self.repo.search_customer_records(query="Bio", limit=5, agent_context=self.agent_1)
        c2 = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(c2["total_invocations"], 2)
        self.assertEqual(c2["successful_invocations"], 2)

        # Operation 3: export
        self.repo.export_customer_records(format="csv", limit=50, agent_context=self.agent_1)
        c3 = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(c3["total_invocations"], 3)
        self.assertEqual(c3["successful_invocations"], 3)

        # Pre-validation failure MUST NOT increment counters
        with self.assertRaises(ValueError):
            self.repo.search_customer_records(query="test", limit=-1, agent_context=self.agent_1)
        c_after_fail = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(c_after_fail["total_invocations"], 3)
        self.assertEqual(c_after_fail["successful_invocations"], 3)

        # Untrusted context (missing / None) MUST NOT increment counters
        with self.assertRaises(TypeError):
            self.repo.get_customer_by_id("CUST-101", agent_context=None)
        with self.assertRaises(TypeError):
            self.repo.search_customer_records(query="Bio", agent_context=None)
        with self.assertRaises(TypeError):
            self.repo.export_customer_records(agent_context=None)
        with self.assertRaises(TypeError):
            self.repo.search_customer_records(query="Bio", agent_context="untrusted_string")
        c_after_untrusted = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(c_after_untrusted["total_invocations"], 3)
        self.assertEqual(c_after_untrusted["successful_invocations"], 3)

    # 9. Counter persistence on failure
    def test_counter_persistence_on_failure(self):
        """Verify counter persists entry increment even if database operation fails midway."""
        initial = get_invocation_counts(self.db_path, "crm")
        start_total = initial["total_invocations"]
        start_success = initial["successful_invocations"]

        # Drop the customers table to force query failure after repository entry
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute("DROP TABLE customers;")
            conn.commit()
        finally:
            conn.close()

        # Repository call enters, records invocation, then fails on query
        with self.assertRaises(sqlite3.OperationalError):
            self.repo.get_customer_by_id("CUST-101", self.agent_1)

        after_failure = get_invocation_counts(self.db_path, "crm")
        self.assertEqual(
            after_failure["total_invocations"],
            start_total + 1,
            "total_invocations was not preserved following database operation failure!"
        )
        self.assertEqual(
            after_failure["successful_invocations"],
            start_success,
            "successful_invocations was erroneously incremented despite query failure!"
        )

    # 10. Missing customer handling
    def test_missing_customer_handling(self):
        """Verify querying a non-existent customer returns None without throwing."""
        res = self.repo.get_customer_by_id("CUST-999-NONEXISTENT", self.agent_1)
        self.assertIsNone(res)

    # 11. WAL mode and connection settings
    def test_wal_mode_and_connection_settings(self):
        """Verify WAL mode is enabled for file-backed databases and skipped for in-memory databases."""
        from backend.app.database import get_connection, is_in_memory_db
        
        # File-backed database: journal_mode should be WAL
        conn_file = get_connection(self.db_path)
        try:
            cursor = conn_file.cursor()
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0]
            self.assertEqual(journal_mode.lower(), "wal")
        finally:
            conn_file.close()

        # In-memory database: is_in_memory_db is True, journal_mode remains memory
        self.assertTrue(is_in_memory_db(":memory:"))
        self.assertFalse(is_in_memory_db(self.db_path))
        conn_mem = get_connection(":memory:")
        try:
            cursor = conn_mem.cursor()
            cursor.execute("PRAGMA journal_mode;")
            mem_mode = cursor.fetchone()[0]
            self.assertEqual(mem_mode.lower(), "memory")
        finally:
            conn_mem.close()


if __name__ == "__main__":
    unittest.main()
