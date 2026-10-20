import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import shutil
from datetime import timedelta

DB_PATH = Path(__file__).resolve().parent / "clients.sqlite3"

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ok',
                error_time TEXT,
                ping_ms INTEGER,
                last_seen TEXT
            )
        """)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(clients)").fetchall()]
        if "ping_ms" not in columns:
            conn.execute("ALTER TABLE clients ADD COLUMN ping_ms INTEGER")
        if "last_seen" not in columns:
            conn.execute("ALTER TABLE clients ADD COLUMN last_seen TEXT")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS failure_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT
            )
        """)

        # Indeksy
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failure_client ON failure_history(client_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failure_started ON failure_history(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failure_open ON failure_history(client_id, ended_at)")

def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def get_clients_paginated(search: str = None, page: int = 1, per_page: int = 100, status_filter: str = None):
    offset = (page - 1) * per_page
    with get_db() as conn:
        conditions = []
        params = []

        if search:
            escaped = _escape_like(search.strip())
            conditions.append("client_id LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")
        if status_filter in ("ok", "error"):
            conditions.append("status = ?")
            params.append(status_filter)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        total = conn.execute(f"SELECT COUNT(*) FROM clients {where}", params).fetchone()[0]
        rows = conn.execute(
            f"""
            SELECT * FROM clients
            {where}
            ORDER BY CASE WHEN status = 'error' THEN 0 ELSE 1 END, client_id
            LIMIT ? OFFSET ?
            """,
            params + [per_page, offset]
        ).fetchall()
        return [dict(row) for row in rows], total

def get_all_clients():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM clients ORDER BY CASE WHEN status = 'error' THEN 0 ELSE 1 END, client_id"
        ).fetchall()
        return [dict(row) for row in rows]

def add_client(client_id: str, ip: str, status: str = "ok") -> tuple[bool, str]:
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO clients (client_id, ip, status, last_seen) VALUES (?, ?, ?, ?)",
                (client_id, ip, status, now)
            )
        return True, "Klient dodany"
    except sqlite3.IntegrityError:
        return False, "Klient o tym ID już istnieje"

def delete_client(client_id: str) -> tuple[bool, str]:
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
        if cursor.rowcount == 0:
            return False, "Nie znaleziono klienta"
        return True, "Klient usunięty"

def update_client(old_id: str, new_id: str, new_ip: str) -> tuple[bool, str]:
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "UPDATE clients SET client_id = ?, ip = ? WHERE client_id = ?",
                (new_id, new_ip, old_id)
            )
            if cursor.rowcount == 0:
                return False, "Nie znaleziono klienta"
        return True, "Klient zaktualizowany"
    except sqlite3.IntegrityError:
        return False, "Klient o nowym ID już istnieje"

def update_client_status(client_id: str, status: str, error_time: str = None, ping_ms: int = None, last_seen: str = None):
    with get_db() as conn:
        if status == "ok":
            conn.execute(
                """
                UPDATE clients
                SET status = ?, error_time = NULL, ping_ms = COALESCE(?, ping_ms),
                    last_seen = COALESCE(?, last_seen)
                WHERE client_id = ?
                """,
                (status, ping_ms, last_seen, client_id)
            )
        else:
            conn.execute(
                """
                UPDATE clients
                SET status = ?, error_time = COALESCE(?, error_time)
                WHERE client_id = ?
                """,
                (status, error_time, client_id)
            )

def update_last_seen(client_id: str, last_seen: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE clients SET last_seen = ? WHERE client_id = ?",
            (last_seen, client_id)
        )

def log_failure_start(client_id: str, started_at: str = None):
    if not started_at:
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO failure_history (client_id, started_at) VALUES (?, ?)",
            (client_id, started_at)
        )

def log_failure_end(client_id: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            """
            UPDATE failure_history
            SET ended_at = ?
            WHERE id = (
                SELECT id FROM failure_history
                WHERE client_id = ? AND ended_at IS NULL
                ORDER BY started_at DESC
                LIMIT 1
            )
            """,
            (now, client_id)
        )

def get_failure_history_filtered(
    client_id: str = None,
    date_from: str = None,
    date_to: str = None,
    only_open: bool = False,
    limit: int = 200
):
    with get_db() as conn:
        conditions = []
        params = []

        if client_id:
            escaped = _escape_like(client_id.strip())
            conditions.append("client_id LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")
        if date_from:
            conditions.append("started_at >= ?")
            params.append(date_from)
        if date_to:
            conditions.append("started_at <= ?")
            params.append(date_to + " 23:59:59")
        if only_open:
            conditions.append("ended_at IS NULL")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        rows = conn.execute(
            f"""
            SELECT * FROM failure_history
            {where}
            ORDER BY started_at DESC
            LIMIT ?
            """,
            params + [limit]
        ).fetchall()
        return [dict(row) for row in rows]

BACKUP_DIR = Path(__file__).resolve().parent / "backups"

def backup_database():
    """Tworzy kopię zapasową bazy."""
    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"clients_{timestamp}.sqlite3"
    shutil.copy2(DB_PATH, backup_path)
    # Zostaw tylko ostatnie 14 kopii
    backups = sorted(BACKUP_DIR.glob("clients_*.sqlite3"))
    for old in backups[:-14]:
        old.unlink(missing_ok=True)
    return backup_path

def cleanup_old_failures(days: int = 90):
    """Usuwa awarie starsze niż podana liczba dni."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM failure_history WHERE started_at < ?",
            (cutoff,)
        )
        return cursor.rowcount

def get_overnight_failures(date_from: str = None, date_to: str = None):
    """Awarie z okresu 17:00–09:00."""
    with get_db() as conn:
        query = """
            SELECT * FROM failure_history
            WHERE (
                (strftime('%H:%M', started_at) >= '17:00' OR strftime('%H:%M', started_at) < '09:00')
                OR
                (ended_at IS NOT NULL AND (
                    strftime('%H:%M', ended_at) >= '17:00' OR strftime('%H:%M', ended_at) < '09:00'
                ))
                OR
                (ended_at IS NULL)
            )
        """
        params = []
        if date_from:
            query += " AND started_at >= ?"
            params.append(date_from)
        if date_to:
            query += " AND started_at <= ?"
            params.append(date_to + " 23:59:59")

        query += " ORDER BY started_at DESC LIMIT 500"
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

def clear_failure_history() -> int:
    """Usuwa całą historię awarii. Zwraca liczbę usuniętych rekordów."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM failure_history")
        return cursor.rowcount