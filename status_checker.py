from datetime import datetime
import logging
import threading
import time
import json
from pathlib import Path
import database
import huawei

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

refresh_lock = threading.Lock()

DEVICES_PATH = Path(__file__).resolve().parent / "devices.json"

def load_devices() -> list[dict]:
    if not DEVICES_PATH.exists():
        return []
    try:
        with open(DEVICES_PATH, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as e:
        logger.error(f"Błąd ładowania devices.json: {e}")
        return []

MAX_RETRIES = 3
RETRY_DELAY = 2

def get_arp_with_retry(dev: dict) -> set[str] | None:
    """Zwraca zbiór IP lub None przy całkowitym niepowodzeniu."""
    name = dev.get("name", dev["host"])
    port = dev.get("port", 22)
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Pobieram ARP z {name} (próba {attempt}/{MAX_RETRIES})")
            arp = huawei.get_arp_table(
                host=dev["host"],
                username=dev["username"],
                password=dev["password"],
                port=port,
            )
            if arp is not None:
                logger.info(f"{name} → {len(arp)} wpisów ARP")
                return arp
            else:
                logger.warning(f"{name} → błąd odczytu (próba {attempt})")
        except Exception as e:
            logger.warning(f"{name} → błąd SSH (próba {attempt}): {type(e).__name__}: {e}")

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)

    logger.error(f"{name} → nie udało się pobrać ARP po {MAX_RETRIES} próbach")
    return None

def get_local_arp() -> set[str] | None:
    """Zwraca zbiór IP lub None przy błędzie odczytu."""
    import subprocess
    import platform
    import re

    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            logger.error("Lokalny ARP zwrócił błąd")
            return None

        arp: set[str] = set()
        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        for line in result.stdout.splitlines():
            match = ip_re.search(line)
            if match:
                ip = match.group(1)
                if not ip.endswith(".255") and not ip.startswith("224."):
                    arp.add(ip)
        logger.info(f"Lokalna tabela ARP: {len(arp)} wpisów")
        return arp
    except Exception as e:
        logger.error(f"Błąd lokalnego ARP: {type(e).__name__}: {e}")
        return None

def refresh_all_statuses():
    if not refresh_lock.acquire(blocking=False):
        logger.info("Odświeżanie już trwa — pomijam")
        return

    try:
        logger.info("=== Rozpoczynam sprawdzanie statusów ===")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        arp_table: set[str] = set()
        local_ok = False
        ssh_ok = False

        # Lokalny ARP
        local_arp = get_local_arp()
        if local_arp is not None:
            arp_table.update(local_arp)
            local_ok = True
            logger.info(f"Lokalny ARP: {len(local_arp)} wpisów")
        else:
            logger.warning("Nie udało się odczytać lokalnego ARP")

        # Urządzenia SSH — zawsze próbujemy
        devices = load_devices()
        if devices:
            for dev in devices:
                device_arp = get_arp_with_retry(dev)
                if device_arp is not None:
                    arp_table.update(device_arp)
                    ssh_ok = True
                    logger.info(f"SSH {dev.get('name', dev['host'])}: {len(device_arp)} wpisów")
                else:
                    logger.warning(f"Urządzenie {dev.get('name', dev['host'])} nie odpowiedziało")
        else:
            logger.info("Brak urządzeń SSH")

        # Nie aktualizuj statusów, jeśli nie mamy żadnych danych
        if not local_ok and not ssh_ok:
            logger.error("Brak jakichkolwiek danych ARP — pomijam aktualizację statusów")
            return

        # Dodatkowa ochrona: jeśli mamy tylko lokalny ARP i jest on bardzo mały
        if local_ok and not ssh_ok and len(arp_table) < 3:
            logger.warning(f"Tylko lokalny ARP z {len(arp_table)} wpisami — pomijam aktualizację (ryzyko fałszywych awarii)")
            return

        logger.info(f"Łącznie wpisów ARP: {len(arp_table)}")

        clients = database.get_all_clients()

        for client in clients:
            ip = client["ip"]
            client_id = client["client_id"]
            old_status = client["status"]
            last_seen = client.get("last_seen")

            in_arp = ip in arp_table

            if in_arp:
                database.update_last_seen(client_id, now)
                if old_status == "error":
                    database.log_failure_end(client_id)
                    database.update_client_status(client_id, "ok", last_seen=now)
                else:
                    database.update_client_status(client_id, "ok", last_seen=now)
            else:
                if old_status != "error":
                    start_time = last_seen if last_seen else now
                    database.log_failure_start(client_id, started_at=start_time)
                    database.update_client_status(client_id, "error", error_time=start_time)

        logger.info(f"=== Zakończono sprawdzanie {len(clients)} klientów ===")

    except Exception as e:
        logger.error(f"Błąd odświeżania: {type(e).__name__}: {e}")
    finally:
        refresh_lock.release()