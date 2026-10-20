import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
import shutil
import os

DB_PATH = Path(__file__).resolve().parent / "clients.sqlite3"
BACKUP_DIR = Path(__file__).resolve().parent / "backups"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

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
        conn.commit()

def _safe_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def get_all_clients():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM clients ORDER BY client_id").fetchall()
        return [dict(row) for row in rows]

def get_clients_paginated(search: str = None, page: int = 1, per_page: int = 100, status_filter: str = None):
    with get_db() as conn:
        query = "SELECT * FROM clients"
        count_query = "SELECT COUNT(*) FROM clients"
        params = []
        conditions = []

        if search:
            conditions.append("client_id LIKE ?")
            params.append(f"%{search}%")
        if status_filter:
            conditions.append("status = ?")
            params.append(status_filter)

        if conditions:
            where = " WHERE " + " AND ".join(conditions)
            query += where
            count_query += where

        total = conn.execute(count_query, params).fetchone()[0]

        query += " ORDER BY client_id LIMIT ? OFFSET ?"
        offset = (page - 1) * per_page
        rows = conn.execute(query, params + [per_page, offset]).fetchall()
        return [dict(row) for row in rows], total

def add_client(client_id: str, ip: str, status: str = "ok"):
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO clients (client_id, ip, status) VALUES (?, ?, ?)",
                (client_id, ip, status)
            )
            conn.commit()
            return True, "Klient dodany"
        except sqlite3.IntegrityError:
            return False, "Klient o tym ID już istnieje"

def delete_client(client_id: str):
    with get_db() as conn:
        conn.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
        conn.execute("DELETE FROM failure_history WHERE client_id = ?", (client_id,))
        conn.commit()
        return True, "Klient usunięty"

def update_client(old_id: str, new_id: str, new_ip: str):
    with get_db() as conn:
        try:
            conn.execute(
                "UPDATE clients SET client_id = ?, ip = ? WHERE client_id = ?",
                (new_id, new_ip, old_id)
            )
            conn.execute(
                "UPDATE failure_history SET client_id = ? WHERE client_id = ?",
                (new_id, old_id)
            )
            conn.commit()
            return True, "Klient zaktualizowany"
        except sqlite3.IntegrityError:
            return False, "Nowe ID już istnieje"

def update_client_status(client_id: str, status: str, error_time: str = None, last_seen: str = None):
    with get_db() as conn:
        if status == "error":
            conn.execute(
                "UPDATE clients SET status = ?, error_time = ? WHERE client_id = ?",
                (status, error_time, client_id)
            )
        else:
            conn.execute(
                "UPDATE clients SET status = ?, error_time = NULL, last_seen = COALESCE(?, last_seen) WHERE client_id = ?",
                (status, last_seen, client_id)
            )
        conn.commit()

def update_last_seen(client_id: str, when: str):
    with get_db() as conn:
        conn.execute("UPDATE clients SET last_seen = ? WHERE client_id = ?", (when, client_id))
        conn.commit()

def log_failure_start(client_id: str, started_at: str = None):
    if not started_at:
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM failure_history WHERE client_id = ? AND ended_at IS NULL LIMIT 1",
            (client_id,)
        ).fetchone()
        if existing:
            return
        conn.execute(
            "INSERT INTO failure_history (client_id, started_at) VALUES (?, ?)",
            (client_id, started_at)
        )
        conn.commit()

def log_failure_end(client_id: str):
    ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            """UPDATE failure_history SET ended_at = ?
               WHERE client_id = ? AND ended_at IS NULL
               ORDER BY started_at DESC LIMIT 1""",
            (ended_at, client_id)
        )
        conn.commit()

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

def _overlaps_night(start: datetime, end: datetime) -> bool:
    """Czy przedział [start, end] przecina się z 17:00–09:00."""
    current = start
    while current < end:
        day_start = current.replace(hour=17, minute=0, second=0, microsecond=0)
        if current.hour < 9:
            day_start = (current - timedelta(days=1)).replace(hour=17, minute=0, second=0, microsecond=0)
        night_end = day_start + timedelta(hours=16)  # 17:00 + 16h = 09:00 next day
        if current < night_end and end > day_start:
            return True
        current = night_end
        if current <= start:
            current += timedelta(days=1)
    return False

def _overlaps_night_in_range(start: datetime, end: datetime, date_from: str | None, date_to: str | None) -> bool:
    range_start = datetime.strptime(date_from, "%Y-%m-%d") if date_from else start
    range_end = datetime.strptime(date_to + " 23:59:59", "%Y-%m-%d %H:%M:%S") if date_to else end
    check_start = max(start, range_start)
    check_end = min(end, range_end)
    if check_start >= check_end:
        return False
    return _overlaps_night(check_start, check_end)

def get_overnight_failures(date_from: str = None, date_to: str = None):
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
        query += " ORDER BY started_at DESC LIMIT 5000"

        rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            item = dict(row)
            start = _safe_parse_datetime(item.get("started_at"))
            if not start:
                continue
            end = _safe_parse_datetime(item.get("ended_at")) or datetime.now()

            if not _overlaps_night_in_range(start, end, date_from, date_to):
                continue

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

def clear_failure_history():
    with get_db() as conn:
        cur = conn.execute("DELETE FROM failure_history")
        conn.commit()
        return cur.rowcount

def cleanup_old_failures(days: int = 90):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM failure_history WHERE ended_at IS NOT NULL AND ended_at < ?",
            (cutoff,)
        )
        conn.commit()
        return cur.rowcount

def backup_database():
    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_DIR / f"clients_{timestamp}.sqlite3"
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(dest)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()
    return dest