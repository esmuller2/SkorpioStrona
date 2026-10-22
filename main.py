from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import bcrypt
import os
import ipaddress
import logging
import time
import secrets
from collections import defaultdict
from threading import Lock
import csv
import io
from datetime import datetime
from urllib.parse import urlencode
import database
import status_checker

logger = logging.getLogger(__name__)
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.getenv("APP_SECRET")
PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
USER_PASSWORD_HASH = os.getenv("USER_PASSWORD_HASH")

if not SECRET_KEY or not PASSWORD_HASH:
    raise RuntimeError(
        "Brak wymaganych zmiennych środowiskowych: APP_SECRET i ADMIN_PASSWORD_HASH. "
        "Ustaw je w pliku .env"
    )

ACCOUNTS = {
    "admin": {"hash": PASSWORD_HASH, "role": "admin", "label": "admin"},
}
if USER_PASSWORD_HASH:
    ACCOUNTS["uzytkownik"] = {
        "hash": USER_PASSWORD_HASH,
        "role": "user",
        "label": "użytkownik",
    }

login_attempts = defaultdict(list)
login_attempts_lock = Lock()
MAX_ATTEMPTS = 5
LOCK_TIME = 300

def get_client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"

def is_locked(ip: str) -> bool:
    now = time.time()
    with login_attempts_lock:
        for address, attempts in list(login_attempts.items()):
            recent = [timestamp for timestamp in attempts if now - timestamp < LOCK_TIME]
            if recent:
                login_attempts[address] = recent
            else:
                login_attempts.pop(address, None)
        locked = len(login_attempts.get(ip, [])) >= MAX_ATTEMPTS
        if locked:
            logger.warning("Logowanie zablokowane dla %s (za dużo prób)", ip)
        return locked

def record_login_failure(ip: str) -> None:
    with login_attempts_lock:
        login_attempts[ip].append(time.time())
        count = len(login_attempts[ip])
    logger.warning("Nieudane logowanie z %s (%s/%s)", ip, count, MAX_ATTEMPTS)

def generate_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return str(token)

def validate_csrf(request: Request, token: str | None) -> bool:
    expected = request.session.get("csrf_token")
    if not expected or not token or not secrets.compare_digest(expected, token):
        return False
    return True

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(
        status_checker.refresh_all_statuses,
        "interval",
        seconds=30,
        id="status_refresh",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=15,
        next_run_time=datetime.now(),
    )
    scheduler.add_job(
        database.backup_database,
        "cron",
        hour=3,
        minute=0,
        id="daily_backup",
        replace_existing=True
    )
    scheduler.add_job(
        lambda: database.cleanup_old_failures(90),
        "cron",
        hour=3,
        minute=30,
        id="cleanup_failures",
        replace_existing=True
    )
    scheduler.start()
    logger.info("Scheduler uruchomiony (statusy co 30s, backup 03:00, czyszczenie 03:30)")
    try:
        yield
    finally:
        scheduler.shutdown()

app = FastAPI(title="Huawei Clients Monitor", lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="session",
    max_age=int(os.getenv("SESSION_MAX_AGE", str(60 * 60 * 8))),
    same_site="lax",
    https_only=os.getenv("HTTPS_ONLY", "false").lower() == "true",
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "templates" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

database.init_db()

def get_current_user(request: Request):
    return request.session.get("user")

def get_current_role(request: Request) -> str:
    return request.session.get("role") or ""

def require_login(request: Request):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)
    return None

def require_admin(request: Request):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)
    if get_current_role(request) != "admin":
        return RedirectResponse(url="/?error=Brak uprawnień", status_code=303)
    return None

def parse_date_range(date_from: str | None, date_to: str | None) -> tuple[str | None, str | None]:
    parsed = []
    for value in (date_from, date_to):
        if not value:
            parsed.append(None)
            continue
        try:
            parsed_date = datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Nieprawidłowy format daty") from exc
        if parsed_date.isoformat() != value:
            raise HTTPException(status_code=400, detail="Nieprawidłowy format daty")
        parsed.append(value)
    if parsed[0] and parsed[1] and parsed[0] > parsed[1]:
        raise HTTPException(status_code=400, detail="Data początkowa jest późniejsza niż końcowa")
    return parsed[0], parsed[1]

def safe_csv_value(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value

@app.get("/login")
def login_page(request: Request, reauth: str = None):
    if get_current_user(request) and reauth != "1":
        return RedirectResponse(url="/", status_code=303)
    csrf_token = generate_csrf_token(request)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"csrf_token": csrf_token}
    )

@app.post("/login")
def login(
    request: Request,
    username: str | None = Form(None),
    password: str | None = Form(None),
    csrf_token: str | None = Form(None)
):
    client_ip = get_client_ip(request)

    if is_locked(client_ip):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Zbyt wiele nieudanych prób. Spróbuj za 5 minut.",
                "csrf_token": generate_csrf_token(request)
            }
        )

    if not validate_csrf(request, csrf_token):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Nieprawidłowy token bezpieczeństwa. Odśwież stronę.",
                "csrf_token": generate_csrf_token(request)
            }
        )

    account_name = (username or "").strip().lower()
    account = ACCOUNTS.get(account_name)
    if not password or len(password) > 128 or not account:
        record_login_failure(client_ip)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Nieprawidłowy login lub hasło",
                "csrf_token": generate_csrf_token(request)
            }
        )

    try:
        password_bytes = password.encode("utf-8")
        hash_bytes = account["hash"].strip().strip('"').strip("'").encode("utf-8")
        if bcrypt.checkpw(password_bytes, hash_bytes):
            request.session.clear()
            request.session["user"] = account_name
            request.session["role"] = account["role"]
            with login_attempts_lock:
                login_attempts.pop(client_ip, None)
            return RedirectResponse(url="/?tabauth=1", status_code=303)
    except ValueError:
        logger.error("Nieprawidłowy format hasha hasła lub hasło przekracza limit bcrypt")

    record_login_failure(client_ip)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": "Nieprawidłowy login lub hasło",
            "csrf_token": generate_csrf_token(request)
        }
    )

@app.post("/logout")
def logout(request: Request, csrf_token: str | None = Form(None)):
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(
            url=f"/login?{urlencode({'error': 'Nieprawidłowy token bezpieczeństwa'})}",
            status_code=303
        )
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/")
def home(
    request: Request,
    msg: str = None,
    error: str = None,
    page: int = 1,
    search: str = None,
    status_filter: str = None,
):
    denied = require_login(request)
    if denied:
        return denied

    per_page = 100
    _, total = database.get_clients_paginated(search, 1, 1, status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    clients, _ = database.get_clients_paginated(search, page, per_page, status_filter)
    errors = [c for c in clients if c["status"] == "error"]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "clients": clients,
            "errors": errors,
            "msg": msg,
            "error": error,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "search": search or "",
            "status_filter": status_filter or "",
            "csrf_token": generate_csrf_token(request),
            "role": get_current_role(request),
            "username": get_current_user(request),
        },
    )

@app.get("/history")
def history_page(
    request: Request,
    client_id: str = None,
    date_from: str = None,
    date_to: str = None,
    only_open: bool = False,
    msg: str = None,
    error: str = None,
):
    denied = require_login(request)
    if denied:
        return denied

    date_from, date_to = parse_date_range(date_from, date_to)

    history = database.get_failure_history_filtered(
        client_id=client_id,
        date_from=date_from,
        date_to=date_to,
        only_open=only_open,
        limit=300
    )

    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={
            "history": history,
            "client_id": client_id or "",
            "date_from": date_from or "",
            "date_to": date_to or "",
            "only_open": only_open,
            "msg": msg,
            "error": error,
            "csrf_token": generate_csrf_token(request),
            "role": get_current_role(request),
            "username": get_current_user(request),
        },
    )

@app.get("/overnight")
def overnight_page(
    request: Request,
    date_from: str = None,
    date_to: str = None,
    msg: str = None,
    error: str = None,
):
    denied = require_login(request)
    if denied:
        return denied

    date_from, date_to = parse_date_range(date_from, date_to)

    history = database.get_overnight_failures(
        date_from=date_from,
        date_to=date_to
    )

    return templates.TemplateResponse(
        request=request,
        name="overnight.html",
        context={
            "history": history,
            "date_from": date_from or "",
            "date_to": date_to or "",
            "msg": msg,
            "error": error,
            "csrf_token": generate_csrf_token(request),
            "role": get_current_role(request),
            "username": get_current_user(request),
        },
    )

@app.get("/export/history")
def export_history_csv(
    request: Request,
    client_id: str = None,
    date_from: str = None,
    date_to: str = None,
    only_open: bool = False,
):
    denied = require_login(request)
    if denied:
        return denied

    date_from, date_to = parse_date_range(date_from, date_to)
    history = database.get_failure_history_filtered(
        client_id=client_id,
        date_from=date_from,
        date_to=date_to,
        only_open=only_open,
        limit=5000,
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID Klienta", "Start", "Koniec", "Czas trwania"])
    for item in history:
        writer.writerow([
            safe_csv_value(item.get("client_id") or ""),
            safe_csv_value(item.get("started_at") or ""),
            safe_csv_value(item.get("ended_at") or "trwa"),
            safe_csv_value(item.get("duration") or ""),
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=historia_awarii.csv"},
    )


@app.get("/export/overnight")
def export_overnight_csv(
    request: Request,
    date_from: str = None,
    date_to: str = None,
):
    denied = require_login(request)
    if denied:
        return denied

    date_from, date_to = parse_date_range(date_from, date_to)
    history = database.get_overnight_failures(date_from=date_from, date_to=date_to)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID Klienta", "Start", "Koniec", "Czas trwania"])
    for item in history:
        writer.writerow([
            safe_csv_value(item.get("client_id") or ""),
            safe_csv_value(item.get("started_at") or ""),
            safe_csv_value(item.get("ended_at") or "trwa"),
            safe_csv_value(item.get("duration") or ""),
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=raport_nocny.csv"},
    )

@app.post("/add")
def add_client(
    request: Request,
    client_id: str = Form(...),
    ip: str = Form(...),
    csrf_token: str | None = Form(None)
):
    denied = require_admin(request)
    if denied:
        return denied
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(url="/?error=Nieprawidłowy token bezpieczeństwa", status_code=303)

    client_id = client_id.strip()
    ip = ip.strip()

    if not client_id or len(client_id) > 50 or len(client_id) < 1:
        return RedirectResponse(url="/?error=Nieprawidłowe ID klienta", status_code=303)
    try:
        parsed_ip = ipaddress.ip_address(ip)
        if parsed_ip.version != 4:
            raise ValueError("IPv4 required")
    except ValueError:
        return RedirectResponse(url="/?error=Nieprawidłowy adres IP", status_code=303)

    success, message = database.add_client(client_id, ip, "ok")
    return RedirectResponse(url=f"/?{'msg' if success else 'error'}={message}", status_code=303)

@app.post("/delete")
def delete_client(
    request: Request,
    client_id: str = Form(...),
    csrf_token: str | None = Form(None)
):
    denied = require_admin(request)
    if denied:
        return denied
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(url="/?error=Nieprawidłowy token bezpieczeństwa", status_code=303)
    success, message = database.delete_client(client_id)
    return RedirectResponse(url=f"/?{'msg' if success else 'error'}={message}", status_code=303)

@app.post("/edit")
def edit_client(
    request: Request,
    old_client_id: str = Form(...),
    new_client_id: str = Form(...),
    new_ip: str = Form(...),
    csrf_token: str | None = Form(None)
):
    denied = require_admin(request)
    if denied:
        return denied
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(url="/?error=Nieprawidłowy token bezpieczeństwa", status_code=303)

    new_client_id = new_client_id.strip()
    new_ip = new_ip.strip()

    if not new_client_id or len(new_client_id) > 50 or len(new_client_id) < 1:
        return RedirectResponse(url="/?error=Nieprawidłowe ID klienta", status_code=303)
    try:
        parsed_ip = ipaddress.ip_address(new_ip)
        if parsed_ip.version != 4:
            raise ValueError("IPv4 required")
    except ValueError:
        return RedirectResponse(url="/?error=Nieprawidłowy adres IP", status_code=303)

    success, message = database.update_client(old_client_id, new_client_id, new_ip)
    return RedirectResponse(url=f"/?{'msg' if success else 'error'}={message}", status_code=303)

@app.post("/refresh-status")
def refresh_status(request: Request, csrf_token: str | None = Form(None)):
    denied = require_admin(request)
    if denied:
        return denied
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(
            url=f"/?{urlencode({'error': 'Nieprawidłowy token bezpieczeństwa'})}",
            status_code=303
        )
    refreshed = status_checker.refresh_all_statuses()
    if not refreshed:
        return RedirectResponse(
            url=f"/?{urlencode({'error': 'Nie udało się odświeżyć statusów. Sprawdź logi serwera.'})}",
            status_code=303
        )
    return RedirectResponse(url="/?msg=Statusy zostały odświeżone", status_code=303)

@app.post("/backup-now")
def backup_now(request: Request, csrf_token: str | None = Form(None)):
    denied = require_admin(request)
    if denied:
        return denied
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(
            url=f"/?{urlencode({'error': 'Nieprawidłowy token bezpieczeństwa'})}",
            status_code=303
        )
    path = database.backup_database()
    return RedirectResponse(url=f"/?msg=Backup zapisany: {path.name}", status_code=303)

@app.post("/cleanup-now")
def cleanup_now(request: Request, csrf_token: str | None = Form(None)):
    denied = require_admin(request)
    if denied:
        return denied
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(
            url=f"/?{urlencode({'error': 'Nieprawidłowy token bezpieczeństwa'})}",
            status_code=303
        )
    deleted = database.cleanup_old_failures(90)
    return RedirectResponse(url=f"/?msg=Usunięto {deleted} starych awarii", status_code=303)

@app.post("/clear-history")
def clear_history(
    request: Request,
    csrf_token: str | None = Form(None),
    next: str = Form("/history")
):
    next_path = next if next in {"/history", "/overnight"} else "/history"
    denied = require_admin(request)
    if denied:
        return denied
    if not validate_csrf(request, csrf_token):
        return RedirectResponse(
            url=f"{next_path}?{urlencode({'error': 'Nieprawidłowy token bezpieczeństwa'})}",
            status_code=303
        )
    deleted = database.clear_failure_history()
    return RedirectResponse(
        url=f"{next_path}?{urlencode({'msg': f'Usunięto {deleted} wpisów historii'})}",
        status_code=303
    )

@app.get("/api/clients")
def api_clients(
    request: Request,
    page: int = 1,
    search: str = None,
    status_filter: str = None,
):
    if not get_current_user(request):
        raise HTTPException(status_code=401, detail="unauthorized")

    per_page = 100
    _, total = database.get_clients_paginated(search, 1, 1, status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    clients, _ = database.get_clients_paginated(search, page, per_page, status_filter)
    errors = [c for c in clients if c["status"] == "error"]

    return {
        "clients": clients,
        "errors": errors,
        "page": page,
        "total_pages": total_pages,
        "total": total,
    }

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}