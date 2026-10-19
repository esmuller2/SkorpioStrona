from datetime import datetime
import logging
import threading
import time
import database
import huawei

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

refresh_lock = threading.Lock()

DEVICES = [
    # {
    #     "name": "Huawei-Core",
    #     "host": "192.168.1.1",
    #     "username": "admin",
    #     "password": "haslo",
    #     "port": 22,
    # },
]

MAX_RETRIES = 3
RETRY_DELAY = 2

def get_arp_with_retry(dev: dict) -> set[str]:
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
            if arp:
                logger.info(f"{name} → {len(arp)} wpisów ARP")
                return arp
            else:
                logger.warning(f"{name} → pusta odpowiedź (próba {attempt})")
        except Exception as e:
            logger.warning(f"{name} → błąd SSH (próba {attempt}): {type(e).__name__}: {e}")

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)

    logger.error(f"{name} → nie udało się pobrać ARP po {MAX_RETRIES} próbach")
    return set()

def get_local_arp() -> set[str]:
    import subprocess
    import platform
    import re

    arp: set[str] = set()
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
                    arp.add(ip)
        logger.info(f"Lokalna tabela ARP: {len(arp)} wpisów")
        return arp
    except Exception as e:
        logger.error(f"Błąd lokalnego ARP: {type(e).__name__}: {e}")
        return set()

def refresh_all_statuses():
    if not refresh_lock.acquire(blocking=False):
        logger.info("Odświeżanie już trwa — pomijam")
        return

    try:
        logger.info("=== Rozpoczynam sprawdzanie statusów ===")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        arp_table: set[str] = get_local_arp()

        if DEVICES:
            for dev in DEVICES:
                device_arp = get_arp_with_retry(dev)
                arp_table.update(device_arp)
        else:
            logger.info("Brak urządzeń SSH — używam tylko lokalnego ARP")

        logger.info(f"Łącznie wpisów ARP: {len(arp_table)}")

        clients = database.get_all_clients()

        for client in clients:
            ip = client["ip"]
            client_id = client["client_id"]
            old_status = client["status"]
            last_seen = client.get("last_seen")

            in_arp = ip in arp_table

            if in_arp:
                # Widoczny w sieci — aktualizujemy last_seen
                database.update_last_seen(client_id, now)
                if old_status == "error":
                    database.log_failure_end(client_id)
                    database.update_client_status(client_id, "ok", last_seen=now)
                else:
                    database.update_client_status(client_id, "ok", last_seen=now)
            else:
                # Nie ma w ARP
                if old_status != "error":
                    # Nowa awaria — startujemy od ostatniego momentu, kiedy był widoczny
                    start_time = last_seen if last_seen else now
                    database.log_failure_start(client_id, started_at=start_time)
                    database.update_client_status(client_id, "error", error_time=start_time)

        logger.info(f"=== Zakończono sprawdzanie {len(clients)} klientów ===")

    except Exception as e:
        logger.error(f"Błąd odświeżania: {type(e).__name__}: {e}")
    finally:
        refresh_lock.release()