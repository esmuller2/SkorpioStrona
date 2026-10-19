from datetime import datetime
import logging
import threading
import time
import database
import huawei

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

refresh_lock = threading.Lock()

# ============================================================
# KONFIGURACJA URZĄDZEŃ (opcjonalna)
# ============================================================
DEVICES = [
    # {
    #     "name": "Huawei-Core",
    #     "host": "192.168.1.1",
    #     "username": "admin",
    #     "password": "haslo",
    #     "device_type": "huawei",
    #     "port": 22
    # },
]
# ============================================================

MAX_RETRIES = 3
RETRY_DELAY = 2  # sekundy między próbami

def get_arp_with_retry(dev: dict) -> dict:
    """Pobiera ARP z retry."""
    name = dev.get("name", dev["host"])
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Pobieram ARP z {name} (próba {attempt}/{MAX_RETRIES})")
            arp = huawei.get_arp_table(
                host=dev["host"],
                username=dev["username"],
                password=dev["password"],
                device_type=dev.get("device_type", "huawei"),
                port=dev.get("port", 22)
            )
            if arp:
                logger.info(f"{name} → {len(arp)} wpisów ARP")
                return arp
            else:
                logger.warning(f"{name} → pusta odpowiedź (próba {attempt})")
        except Exception as e:
            logger.warning(f"{name} → błąd SSH (próba {attempt}): {type(e).__name__}")

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)

    logger.error(f"{name} → nie udało się pobrać ARP po {MAX_RETRIES} próbach")
    return {}

def get_local_arp() -> dict:
    """Lokalna tabela ARP (Windows/Linux)."""
    import subprocess
    import platform
    import re

    arp = {}
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            return arp

        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        for line in result.stdout.splitlines():
            match = ip_re.search(line)
            if match:
                ip = match.group(1)
                if not ip.endswith(".255") and not ip.startswith("224."):
                    arp[ip] = True
        logger.info(f"Lokalna tabela ARP: {len(arp)} wpisów")
        return arp
    except Exception as e:
        logger.error(f"Błąd lokalnego ARP: {type(e).__name__}")
        return {}

def refresh_all_statuses():
    if not refresh_lock.acquire(blocking=False):
        logger.info("Odświeżanie już trwa — pomijam")
        return

    try:
        logger.info("=== Rozpoczynam sprawdzanie statusów ===")

        # Zawsze lokalny ARP
        arp_table = get_local_arp()

        # Dodatkowo z urządzeń (z retry)
        if DEVICES:
            for dev in DEVICES:
                device_arp = get_arp_with_retry(dev)
                arp_table.update(device_arp)
        else:
            logger.info("Brak urządzeń SSH — używam tylko lokalnego ARP")

        logger.info(f"Łącznie wpisów ARP: {len(arp_table)}")

        clients = database.get_all_clients()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for client in clients:
            ip = client["ip"]
            client_id = client["client_id"]
            old_status = client["status"]

            in_arp = ip in arp_table

            if in_arp:
                if old_status == "error":
                    database.log_failure_end(client_id)
                database.update_client_status(client_id, "ok", ping_ms=None)
            else:
                if old_status != "error":
                    database.log_failure_start(client_id)
                    database.update_client_status(client_id, "error", error_time=now)

        logger.info(f"=== Zakończono sprawdzanie {len(clients)} klientów ===")

    except Exception as e:
        logger.error(f"Błąd odświeżania: {type(e).__name__}: {e}")
    finally:
        refresh_lock.release()