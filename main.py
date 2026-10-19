from pathlib import Path
from fastapi import FastAPI, Request, Form, HTTPException
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
import time
import secrets
from collections import defaultdict
import csv
import io
from datetime import datetime
import database
import status_checker

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=True)

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.getenv("APP_SECRET")
PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

if not SECRET_KEY or not PASSWORD_HASH:
    raise RuntimeError(
        "Brak wymaganych zmiennych środowiskowych: APP_SECRET i ADMIN_PASSWORD_HASH. "
        "Ustaw je w pliku .env"
    )

# Rate limiting
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
LOCK_TIME = 300  # 5 minut

def get_client_ip(request: Request) -> str:
    """Bezpieczne pobranie IP klienta."""
    if request.client and request.client.host:
        return request.client.host
    # Fallback na nagłówki (np. za reverse proxy)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return "unknown"

def is_locked(ip: str) -> bool:
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOCK_TIME]
    return len(login_attempts[ip]) >= MAX_ATTEMPTS

def generate_csrf_token(request: Request) -> str:
    token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = token
    return token

def validate_csrf(request: Request, token: str) -> bool:
    expected = request.session.get("csrf_token")
    if not expected or not token or not secrets.compare_digest(expected, token):
        return False
    # Jednorazowy token
    request.session.pop("csrf_token", None)
    return True

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(
        status_checker.refresh_all_statuses,
        "interval",
        seconds=30,
        id="status_refresh",
        replace_existing=True
    )
    scheduler.start()
    print("Scheduler uruchomiony (sprawdzanie statusów co 30 sekund)")
    yield
    scheduler.shutdown()

app = FastAPI(title="Huawei Clients Monitor", lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="session",
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=False,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "templates" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

database.init_db()

def get_current_user(request: Request):
    return request.session.get("user")

@app.get("/login")
def login_page(request: Request):
    if get_current_user(request):
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
    password: str = Form(...),
    csrf_token: str = Form(...)
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

    # Walidacja długości hasła
    if not password or len(password) > 128:
        login_attempts[client_ip].append(time.time())
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Nieprawidłowe hasło",
                "csrf_token": generate_csrf_token(request)
            }
        )

    try:
        password_bytes = password.encode("utf-8")
        hash_bytes = PASSWORD_HASH.strip().strip('"').strip("'").encode("utf-8")
        if bcrypt.checkpw(password_bytes, hash_bytes):
            request.session["user"] = "admin"
            login_attempts[client_ip].clear()
            return RedirectResponse(url="/", status_code=303)
    except Exception:
        pass

    login_attempts[client_ip].append(time.time())
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": "Nieprawidłowe hasło",
            "csrf_token": generate_csrf_token(request)
        }
    )

@app.get("/logout")
def logout(request: Request):
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
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)

    per_page = 100
    clients, total = database.get_clients_paginated(search, page, per_page, status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
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
        },
    )

@app.get("/history")
def history_page(
    request: Request,
    client_id: str = None,
    date_from: str = None,
    date_to: str = None,
    only_open: bool = False,
):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)

    def valid_date(d: str | None) -> str | None:
        if not d:
            return None
        try:
            datetime.strptime(d, "%Y-%m-%d")
            return d
        except ValueError:
            return None

    history = database.get_failure_history_filtered(
        client_id=client_id,
        date_from=valid_date(date_from),
        date_to=valid_date(date_to),
        only_open=only_open,
        limit=300
    )

    for item in history:
        if item["ended_at"]:
            try:
                start = datetime.strptime(item["started_at"], "%Y-%m-%d %H:%M:%S")
                end = datetime.strptime(item["ended_at"], "%Y-%m-%d %H:%M:%S")
                minutes = int((end - start).total_seconds() // 60)
                item["duration"] = f"{minutes} min"
            except Exception:
                item["duration"] = "—"
        else:
            item["duration"] = "trwa"

    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={
            "history": history,
            "client_id": client_id or "",
            "date_from": date_from or "",
            "date_to": date_to or "",
            "only_open": only_open,
        },
    )

@app.get("/export")
def export_csv(request: Request):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)

    clients = database.get_all_clients()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID Klienta", "Adres IP", "Status", "Czas awarii", "Ping (ms)"])
    for c in clients:
        writer.writerow([
            c["client_id"],
            c["ip"],
            c["status"],
            c.get("error_time") or "",
            c.get("ping_ms") or ""
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=klienci.csv"}
    )

@app.post("/add")
def add_client(request: Request, client_id: str = Form(...), ip: str = Form(...)):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)

    client_id = client_id.strip()
    ip = ip.strip()

    if not client_id or len(client_id) > 50 or len(client_id) < 1:
        return RedirectResponse(url="/?error=Nieprawidłowe ID klienta", status_code=303)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return RedirectResponse(url="/?error=Nieprawidłowy adres IP", status_code=303)

    success, message = database.add_client(client_id, ip, "ok")
    return RedirectResponse(url=f"/?{'msg' if success else 'error'}={message}", status_code=303)

@app.post("/delete")
def delete_client(request: Request, client_id: str = Form(...)):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)
    success, message = database.delete_client(client_id)
    return RedirectResponse(url=f"/?{'msg' if success else 'error'}={message}", status_code=303)

@app.post("/edit")
def edit_client(
    request: Request,
    old_client_id: str = Form(...),
    new_client_id: str = Form(...),
    new_ip: str = Form(...),
):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)

    new_client_id = new_client_id.strip()
    new_ip = new_ip.strip()

    if not new_client_id or len(new_client_id) > 50 or len(new_client_id) < 1:
        return RedirectResponse(url="/?error=Nieprawidłowe ID klienta", status_code=303)
    try:
        ipaddress.ip_address(new_ip)
    except ValueError:
        return RedirectResponse(url="/?error=Nieprawidłowy adres IP", status_code=303)

    success, message = database.update_client(old_client_id, new_client_id, new_ip)
    return RedirectResponse(url=f"/?{'msg' if success else 'error'}={message}", status_code=303)

@app.post("/refresh-status")
def refresh_status(request: Request):
    if not get_current_user(request):
        return RedirectResponse(url="/login", status_code=303)
    status_checker.refresh_all_statuses()
    return RedirectResponse(url="/?msg=Statusy zostały odświeżone", status_code=303)

@app.get("/api/clients")
def api_clients(
    request: Request,
    page: int = 1,
    search: str = None,
    status_filter: str = None,
):
    if not get_current_user(request):
        return {"error": "unauthorized"}

    per_page = 100
    clients, total = database.get_clients_paginated(search, page, per_page, status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    errors = [c for c in clients if c["status"] == "error"]

    return {
        "clients": clients,
        "errors": errors,
        "page": page,
        "total_pages": total_pages,
        "total": total,
    }