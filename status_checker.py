from datetime import datetime
import ipaddress
import logging
import threading
import time
import json
import os
from pathlib import Path
import database
import huawei

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

refresh_lock = threading.Lock()

DEVICES_PATH = Path(__file__).resolve().parent / "devices.json"

class DeviceConfigurationError(ValueError):
    pass


def load_devices() -> list[dict]:
    if not DEVICES_PATH.exists():
        raise DeviceConfigurationError(
            f"Brak {DEVICES_PATH.name}; wymagane urządzenia SSH i zakresy sieci"
        )
    try:
        with open(DEVICES_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise DeviceConfigurationError(f"Nie można odczytać {DEVICES_PATH.name}: {exc}") from exc

    if not isinstance(data, list) or not data:
        raise DeviceConfigurationError("devices.json musi zawierać niepustą listę urządzeń")

    devices = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise DeviceConfigurationError(f"Urządzenie nr {index + 1} musi być obiektem JSON")
        host = item.get("host")
        username = item.get("username")
        password_env = item.get("password_env")
        arp_command = item.get("arp_command", "display arp")
        networks = item.get("networks")
        port = item.get("port", 22)
        if not isinstance(host, str) or not host.strip():
            raise DeviceConfigurationError(f"Urządzenie nr {index + 1}: brak host")
        if not isinstance(username, str) or not username.strip():
            raise DeviceConfigurationError(f"Urządzenie {host}: brak username")
        if not isinstance(password_env, str) or not password_env.strip():
            raise DeviceConfigurationError(f"Urządzenie {host}: brak password_env")
        if not isinstance(arp_command, str) or not arp_command.strip():
            raise DeviceConfigurationError(f"Urządzenie {host}: brak arp_command")
        password = os.getenv(password_env)
        if not password:
            raise DeviceConfigurationError(
                f"Urządzenie {host}: zmienna środowiskowa {password_env} nie jest ustawiona"
            )
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise DeviceConfigurationError(f"Urządzenie {host}: nieprawidłowy port")
        if not isinstance(networks, list) or not networks:
            raise DeviceConfigurationError(f"Urządzenie {host}: wymagane są podsieci w networks")

        parsed_networks = []
        for network in networks:
            try:
                parsed = ipaddress.ip_network(network, strict=False)
            except (TypeError, ValueError) as exc:
                raise DeviceConfigurationError(
                    f"Urządzenie {host}: nieprawidłowa podsieć {network!r}"
                ) from exc
            if parsed.version != 4:
                raise DeviceConfigurationError(
                    f"Urządzenie {host}: monitoring ARP obsługuje obecnie tylko IPv4"
                )
            parsed_networks.append(parsed)

        devices.append({
            "name": str(item.get("name") or host),
            "host": host.strip(),
            "username": username.strip(),
            "password": password,
            "port": port,
            "arp_command": arp_command.strip(),
            "networks": parsed_networks,
        })
    return devices

MAX_RETRIES = 3
RETRY_DELAY = 2

def get_arp_with_retry(dev: dict) -> set[str] | None:
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
                command=dev["arp_command"],
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

def refresh_all_statuses() -> bool:
    if not refresh_lock.acquire(blocking=False):
        logger.info("Odświeżanie już trwa — pomijam")
        return False

    try:
        logger.info("=== Rozpoczynam sprawdzanie statusów ===")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        devices = load_devices()
        clients = database.get_all_clients()
        reports = []
        for dev in devices:
            device_arp = get_arp_with_retry(dev)
            if device_arp is None:
                logger.error("%s: brak wiarygodnego odczytu ARP; odświeżenie anulowane", dev["name"])
                return False
            if not device_arp:
                logger.error("%s: pusta tablica ARP; odświeżenie anulowane", dev["name"])
                return False
            reports.append((dev, device_arp))

        arp_table: set[str] = set()
        verified_networks = set()
        for dev, device_arp in reports:
            arp_table.update(device_arp)
            for network in dev["networks"]:
                if any(ipaddress.ip_address(ip) in network for ip in device_arp):
                    verified_networks.add(network)

        if not arp_table:
            logger.error("Brak danych ARP; odświeżenie anulowane")
            return False

        for client in clients:
            try:
                client_ip = ipaddress.ip_address(client["ip"])
            except ValueError:
                logger.error("Klient %s ma nieprawidłowy IP; odświeżenie anulowane", client["client_id"])
                return False
            if client_ip.version != 4 or not any(
                client_ip in network for network in verified_networks
            ):
                logger.error(
                    "Brak potwierdzonego pokrycia ARP dla klienta %s (%s); odświeżenie anulowane",
                    client["client_id"], client["ip"]
                )
                return False

        logger.info(
            "Zebrano %s adresów ARP z %s urządzeń; pokrycie potwierdzone dla %s klientów",
            len(arp_table), len(devices), len(clients)
        )
        total, online, offline = database.apply_status_snapshot(arp_table, now)

        logger.info(
            "=== Odświeżono %s klientów: online=%s, awaria=%s ===",
            total, online, offline
        )
        return True

    except DeviceConfigurationError as e:
        logger.error("Błędna konfiguracja monitoringu: %s", e)
        return False
    except Exception as e:
        logger.error(f"Błąd odświeżania: {type(e).__name__}: {e}")
        return False
    finally:
        refresh_lock.release()