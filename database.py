import sqlite3
from contextlib import contextmanager
from pathlib import Path
from datetime import date, datetime, time, timedelta

DB_PATH = Path(__file__).resolve().parent / "clients.sqlite3"
BACKUP_DIR = Path(__file__).resolve().parent / "backups"

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS failure_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT
            )
        """)
        client_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(clients)")
        }
        if "ping_ms" not in client_columns:
            conn.execute("ALTER TABLE clients ADD COLUMN ping_ms INTEGER")
        if "last_seen" not in client_columns:
            conn.execute("ALTER TABLE clients ADD COLUMN last_seen TEXT")

        duplicate_groups = conn.execute("""
            SELECT client_id,
                   (SELECT newer.id
                    FROM failure_history AS newer
                    WHERE newer.client_id = failure_history.client_id
                      AND newer.ended_at IS NULL
                    ORDER BY newer.started_at DESC, newer.id DESC
                    LIMIT 1) AS keep_id,
                   MAX(started_at) AS latest_start
            FROM failure_history
            WHERE ended_at IS NULL
            GROUP BY client_id
            HAVING COUNT(*) > 1
        """).fetchall()
        for group in duplicate_groups:
            conn.execute(
                """
                UPDATE failure_history
                SET ended_at = ?
                WHERE client_id = ? AND ended_at IS NULL AND id != ?
                """,
                (group["latest_start"], group["client_id"], group["keep_id"])
            )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failure_client ON failure_history(client_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failure_started ON failure_history(started_at)")
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_failure_one_open_per_client
            ON failure_history(client_id)
            WHERE ended_at IS NULL
        """)

def _safe_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

def get_all_clients():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM clients ORDER BY CASE WHEN status = 'error' THEN 0 ELSE 1 END, client_id"
        ).fetchall()
        return [dict(row) for row in rows]

def get_clients_paginated(search: str = None, page: int = 1, per_page: int = 100, status_filter: str = None):
    per_page = max(1, min(per_page, 500))
    page = max(1, page)
    with get_db() as conn:
        query = "SELECT * FROM clients"
        count_query = "SELECT COUNT(*) FROM clients"
        params = []
        conditions = []

        if search:
            escaped_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("client_id LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped_search}%")
        if status_filter in ("ok", "error"):
            conditions.append("status = ?")
            params.append(status_filter)

        if conditions:
            where = " WHERE " + " AND ".join(conditions)
            query += where
            count_query += where

        total = conn.execute(count_query, params).fetchone()[0]
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)

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
            return True, "Klient dodany"
        except sqlite3.IntegrityError:
            return False, "Klient o tym ID już istnieje"

def delete_client(client_id: str):
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
        if cursor.rowcount == 0:
            return False, "Nie znaleziono klienta"
        conn.execute(
            """
            UPDATE failure_history SET ended_at = ?
            WHERE client_id = ? AND ended_at IS NULL
            """,
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_id)
        )
        return True, "Klient usunięty"

def update_client(old_id: str, new_id: str, new_ip: str):
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "UPDATE clients SET client_id = ?, ip = ? WHERE client_id = ?",
                (new_id, new_ip, old_id)
            )
            if cursor.rowcount == 0:
                return False, "Nie znaleziono klienta"
            conn.execute(
                "UPDATE failure_history SET client_id = ? WHERE client_id = ?",
                (new_id, old_id)
            )
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

def update_last_seen(client_id: str, when: str):
    with get_db() as conn:
        conn.execute("UPDATE clients SET last_seen = ? WHERE client_id = ?", (when, client_id))

def apply_status_snapshot(arp_ips: set[str], checked_at: str) -> tuple[int, int, int]:
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        clients = conn.execute(
            "SELECT client_id, ip, status, error_time, last_seen FROM clients"
        ).fetchall()
        online_count = 0
        offline_count = 0
        for client in clients:
            if client["ip"] in arp_ips:
                online_count += 1
                if client["status"] == "error":
                    conn.execute(
                        """
                        UPDATE failure_history SET ended_at = ?
                        WHERE id = (
                            SELECT id FROM failure_history
                            WHERE client_id = ? AND ended_at IS NULL
                            ORDER BY started_at DESC, id DESC
                            LIMIT 1
                        )
                        """,
                        (checked_at, client["client_id"])
                    )
                conn.execute(
                    """
                    UPDATE clients
                    SET status = 'ok', error_time = NULL, last_seen = ?
                    WHERE client_id = ?
                    """,
                    (checked_at, client["client_id"])
                )
                continue

            offline_count += 1
            if client["status"] != "error":
                start_time = client["last_seen"] or checked_at
                conn.execute(
                    """
                    INSERT INTO failure_history (client_id, started_at)
                    VALUES (?, ?)
                    ON CONFLICT(client_id) WHERE ended_at IS NULL DO NOTHING
                    """,
                    (client["client_id"], start_time)
                )
                conn.execute(
                    "UPDATE clients SET status = 'error', error_time = ? WHERE client_id = ?",
                    (start_time, client["client_id"])
                )
            else:
                has_open_failure = conn.execute(
                    """
                    SELECT 1 FROM failure_history
                    WHERE client_id = ? AND ended_at IS NULL
                    LIMIT 1
                    """,
                    (client["client_id"],)
                ).fetchone()
                if not has_open_failure:
                    conn.execute(
                        "INSERT INTO failure_history (client_id, started_at) VALUES (?, ?)",
                        (client["client_id"], client["error_time"] or checked_at)
                    )
        return len(clients), online_count, offline_count

def log_failure_start(client_id: str, started_at: str = None):
    if not started_at:
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
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

def log_failure_end(client_id: str):
    ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            """UPDATE failure_history SET ended_at = ?
               WHERE id = (
                   SELECT id FROM failure_history
                   WHERE client_id = ? AND ended_at IS NULL
                   ORDER BY started_at DESC
                   LIMIT 1
               )""",
            (ended_at, client_id)
        )

def get_failure_history_filtered(
    client_id: str = None,
    date_from: str = None,
    date_to: str = None,
    only_open: bool = False,
    limit: int = 300,
):
    if limit < 1:
        raise ValueError("Limit musi być dodatni")
    first_date = _parse_date_filter(date_from)
    last_date = _parse_date_filter(date_to)
    if first_date and last_date and first_date > last_date:
        raise ValueError("Data początkowa nie może być późniejsza niż końcowa")

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

        rows = conn.execute(query, params)
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

def _parse_date_filter(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError("Data musi mieć format RRRR-MM-DD") from exc

def _overlaps_night_in_range(start: datetime, end: datetime, date_from: str | None, date_to: str | None) -> bool:
    if end <= start:
        return False
    first_night = _parse_date_filter(date_from) or (start.date() - timedelta(days=1))
    last_night = _parse_date_filter(date_to) or end.date()
    if first_night > last_night:
        return False
    window_start = datetime.combine(first_night, time(17, 0))
    window_end = datetime.combine(last_night + timedelta(days=1), time(9, 0))
    if start < window_end and end > window_start and end - start >= timedelta(days=1):
        return True
    night_date = max(first_night, start.date() - timedelta(days=1))
    last_candidate = min(last_night, end.date())
    while night_date <= last_candidate:
        night_start = datetime.combine(night_date, time(17, 0))
        night_end = datetime.combine(night_date + timedelta(days=1), time(9, 0))
        if start < night_end and end > night_start:
            return True
        night_date += timedelta(days=1)
    return False

def get_overnight_failures(date_from: str = None, date_to: str = None):
    first_night = _parse_date_filter(date_from)
    last_night = _parse_date_filter(date_to)
    if first_night and last_night and first_night > last_night:
        raise ValueError("Data początkowa nie może być późniejsza niż końcowa")

    with get_db() as conn:
        query = "SELECT * FROM failure_history"
        params = []
        conditions = []

        if first_night:
            conditions.append("(ended_at IS NULL OR ended_at >= ?)")
            params.append(datetime.combine(first_night, time(17, 0)).strftime("%Y-%m-%d %H:%M:%S"))
        if last_night:
            conditions.append("started_at < ?")
            params.append(
                datetime.combine(last_night + timedelta(days=1), time(9, 0)).strftime("%Y-%m-%d %H:%M:%S")
            )

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY started_at DESC"

        rows = conn.execute(query, params)

        result = []
        for row in rows:
            item = dict(row)
            start = _safe_parse_datetime(item.get("started_at"))
            if not start:
                continue
            end = _safe_parse_datetime(item.get("ended_at")) or datetime.now()
            if end < start:
                continue

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
        return cur.rowcount

def cleanup_old_failures(days: int = 90):
    if days < 1:
        raise ValueError("Liczba dni musi być dodatnia")
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM failure_history WHERE ended_at IS NOT NULL AND ended_at < ?",
            (cutoff,)
        )
        return cur.rowcount

def backup_database():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    dest = BACKUP_DIR / f"clients_{timestamp}.sqlite3"
    src = sqlite3.connect(DB_PATH)
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    finally:
        src.close()

    backups = sorted(BACKUP_DIR.glob("clients_*.sqlite3"))
    for old_backup in backups[:-14]:
        old_backup.unlink()
    return dest