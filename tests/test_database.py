import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import database


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.db_patch = patch.object(database, "DB_PATH", self.db_path)
        self.db_patch.start()
        database.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_migration_adds_columns_and_consolidates_open_failures(self):
        with database.get_db() as conn:
            conn.execute("DROP INDEX idx_failure_one_open_per_client")
            conn.execute("ALTER TABLE clients RENAME TO clients_new")
            conn.execute("""
                CREATE TABLE clients (
                    client_id TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ok',
                    error_time TEXT
                )
            """)
            conn.execute("DROP TABLE clients_new")
            conn.execute(
                "INSERT INTO failure_history (client_id, started_at) VALUES (?, ?)",
                ("A", "2026-10-20 10:00:00")
            )
            conn.execute(
                "INSERT INTO failure_history (client_id, started_at) VALUES (?, ?)",
                ("A", "2026-10-20 11:00:00")
            )

        database.init_db()
        with database.get_db() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(clients)")}
            failures = conn.execute(
                "SELECT started_at, ended_at FROM failure_history WHERE client_id = 'A' ORDER BY started_at"
            ).fetchall()
        self.assertTrue({"ping_ms", "last_seen"}.issubset(columns))
        self.assertEqual(len(failures), 2)
        self.assertEqual(failures[0]["ended_at"], "2026-10-20 11:00:00")
        self.assertIsNone(failures[1]["ended_at"])

    def test_snapshot_closes_recovered_failure_and_opens_new_failure(self):
        database.add_client("UP", "192.168.1.10")
        database.add_client("DOWN", "192.168.1.11")
        database.update_last_seen("DOWN", "2026-10-20 09:00:00")
        database.update_client_status("UP", "error", error_time="2026-10-20 08:00:00")
        database.log_failure_start("UP", "2026-10-20 08:00:00")

        counts = database.apply_status_snapshot(
            {"192.168.1.10"}, "2026-10-20 12:00:00"
        )
        self.assertEqual(counts, (2, 1, 1))
        clients = {client["client_id"]: client for client in database.get_all_clients()}
        self.assertEqual(clients["UP"]["status"], "ok")
        self.assertEqual(clients["DOWN"]["status"], "error")
        self.assertEqual(clients["DOWN"]["error_time"], "2026-10-20 09:00:00")
        with database.get_db() as conn:
            rows = conn.execute(
                "SELECT client_id, ended_at FROM failure_history ORDER BY client_id"
            ).fetchall()
        self.assertEqual(rows[0]["client_id"], "DOWN")
        self.assertIsNone(rows[0]["ended_at"])
        self.assertEqual(rows[1]["ended_at"], "2026-10-20 12:00:00")

    def test_failure_start_is_idempotent_and_delete_removes_history(self):
        database.add_client("A", "192.168.1.10")
        database.log_failure_start("A", "2026-10-20 10:00:00")
        database.log_failure_start("A", "2026-10-20 11:00:00")
        with database.get_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM failure_history WHERE client_id = 'A'"
            ).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(database.delete_client("A"), (True, "Klient usunięty"))
        self.assertEqual(database.delete_client("missing"), (False, "Nie znaleziono klienta"))
        with database.get_db() as conn:
            history = conn.execute(
                "SELECT COUNT(*) FROM failure_history WHERE client_id = 'A'"
            ).fetchone()[0]
        self.assertEqual(history, 0)

    def test_missing_client_cannot_be_reported_as_updated(self):
        result = database.update_client("missing", "new", "192.168.1.12")
        self.assertEqual(result, (False, "Nie znaleziono klienta"))

    def test_overnight_date_range_includes_following_morning(self):
        with database.get_db() as conn:
            conn.execute(
                """
                INSERT INTO failure_history (client_id, started_at, ended_at)
                VALUES (?, ?, ?)
                """,
                ("NIGHT", "2026-10-20 22:00:00", "2026-10-21 01:00:00")
            )
            conn.execute(
                """
                INSERT INTO failure_history (client_id, started_at, ended_at)
                VALUES (?, ?, ?)
                """,
                ("DAY", "2026-10-21 10:00:00", "2026-10-21 12:00:00")
            )
        result = database.get_overnight_failures("2026-10-20", "2026-10-20")
        self.assertEqual([item["client_id"] for item in result], ["NIGHT"])

    def test_pagination_escapes_wildcards_and_clamps_page(self):
        database.add_client("A%1", "192.168.1.10")
        database.add_client("ABC", "192.168.1.11")
        rows, total = database.get_clients_paginated(search="%", page=999)
        self.assertEqual(total, 1)
        self.assertEqual([row["client_id"] for row in rows], ["A%1"])

    def test_overnight_overlap_handles_malformed_interval(self):
        start = datetime(2026, 10, 20, 22, 0)
        end = datetime(2026, 10, 20, 21, 0)
        self.assertFalse(
            database._overlaps_night_in_range(start, end, "2026-10-20", "2026-10-20")
        )


if __name__ == "__main__":
    unittest.main()
