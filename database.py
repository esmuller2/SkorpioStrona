import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
import shutil

DB_PATH = Path(__file__).resolve().parent / "clients.sqlite3"
BACKUP_DIR = Path(__file__).resolve().parent / "backups"

def _safe_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

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
        with get_db() as conn:
            conn.execute(
                "INSERT INTO clients (client_id, ip, status, last_seen) VALUES (?, ?, ?, NULL)",
                (client_id, ip, status)
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
            # Aktualizuj historię awarii
            conn.execute(
                "UPDATE failure_history SET client_id = ? WHERE client_id = ?",
                (new_id, old_id)
            )
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
        # Sprawdź czy już jest otwarta awaria dla tego klienta
        existing = conn.execute(
            "SELECT id FROM failure_history WHERE client_id = ? AND ended_at IS NULL LIMIT 1",
            (client_id,)
        ).fetchone()
        if existing:
            return  # już otwarta — nie dodawaj kolejnej
        conn.execute(
            "INSERT INTO failure_history (client_id, started_at) VALUES (?, ?)",
            (client_id, started_at)
        )
        conn.commit()

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
    limit: int = 300,
):
    with get_db() as conn:
        query = "SELECT * FROM failure_history"
        params = []
        conditions = []

        if client_id:
            conditions.append("client_id = ?")
            params.append(client_id)
        if date_from:
            conditions.append("started_at >= ?")
            params.append(date_from + " 00:00:00")
        if date_to:
            conditions.append("started_at <= ?")
            params.append(date_to + " 23:59:59")
        if only_open:
            conditions.append("ended_at IS NULL")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        history = [dict(row) for row in rows]

    for item in history:
        start = _safe_parse_datetime(item.get("started_at"))
        end = _safe_parse_datetime(item.get("ended_at"))
        if start and end and end >= start:
            minutes = int((end - start).total_seconds() // 60)
            hours = minutes // 60
            mins = minutes % 60
            if hours > 0 and mins > 0:
                item["duration"] = f"{hours} godz {mins} min"
            elif hours > 0:
                item["duration"] = f"{hours} godz"
            else:
                item["duration"] = f"{mins} min"
        else:
            item["duration"] = "trwa" if not item.get("ended_at") else "—"

    return history

def get_overnight_failures(date_from: str = None, date_to: str = None):
    """Awarie, które przecinają się z oknem 17:00–09:00 w wybranym zakresie dat."""
    with get_db() as conn:
        query = "SELECT * FROM failure_history"
        params = []
        conditions = []

        if date_from:
            conditions.append("(ended_at IS NULL OR ended_at >= ?)")
            params.append(date_from + " 00:00:00")
        if date_to:
            conditions.append("started_at <= ?")
            params.append(date_to + " 23:59:59")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY started_at DESC LIMIT 1000"

        rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            item = dict(row)
            start = _safe_parse_datetime(item.get("started_at"))
            if not start:
                continue
            end = _safe_parse_datetime(item.get("ended_at")) or datetime.now()

            # Sprawdź czy przecina noc W WYBRANYM ZAKRESIE
            if not _overlaps_night_in_range(start, end, date_from, date_to):
                continue

            # Czas trwania (ochrona przed ujemnym)
            if item.get("ended_at"):
                end_dt = _safe_parse_datetime(item.get("ended_at"))
                if end_dt and end_dt >= start:
                    minutes = int((end_dt - start).total_seconds() // 60)
                    hours = minutes // 60
                    mins = minutes % 60
                    if hours > 0 and mins > 0:
                        item["duration"] = f"{hours} godz {mins} min"
                    elif hours > 0:
                        item["duration"] = f"{hours} godz"
                    else:
                        item["duration"] = f"{mins} min"
                else:
                    item["duration"] = "—"
            else:
                item["duration"] = "trwa"

            result.append(item)
            if len(result) >= 500:
                break
        return result


def _overlaps_night_in_range(start: datetime, end: datetime, date_from: str | None, date_to: str | None) -> bool:
    """Czy awaria przecina okno 17:00–09:00 w podanym zakresie dat."""
    # Ogranicz start/end do zakresu filtrów
    range_start = datetime.strptime(date_from, "%Y-%m-%d") if date_from else start
    range_end = datetime.strptime(date_to + " 23:59:59", "%Y-%m-%d %H:%M:%S") if date_to else end

    check_start = max(start, range_start)
    check_end = min(end, range_end)
    if check_start >= check_end:
        return False

    return _overlaps_night(check_start, check_end)

def _overlaps_night(start: datetime, end: datetime) -> bool:
    """Czy przedział przecina się z jakimkolwiek oknem 17:00–09:00."""
    current = start.replace(hour=0, minute=0, second=0, microsecond=0)
    end_day = end.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    while current <= end_day:
        night_start = current.replace(hour=17, minute=0, second=0)
        night_end = (current + timedelta(days=1)).replace(hour=9, minute=0, second=0)
        if start < night_end and end > night_start:
            return True
        current += timedelta(days=1)
    return False

def clear_failure_history() -> int:
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM failure_history")
        return cursor.rowcount

def backup_database():
    """Bezpieczny backup przez API SQLite."""
    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"clients_{timestamp}.sqlite3"

    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(backup_path)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()

    backups = sorted(BACKUP_DIR.glob("clients_*.sqlite3"))
    for old in backups[:-14]:
        old.unlink(missing_ok=True)
    return backup_path

def cleanup_old_failures(days: int = 90):
    """Usuwa zamknięte awarie starsze niż podana liczba dni. Otwarte zostawia."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM failure_history WHERE started_at < ? AND ended_at IS NOT NULL",
            (cutoff,)
        )
        return cursor.rowcount