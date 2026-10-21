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
import telnet_client
import local_arp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

refresh_lock = threading.Lock()

DEVICES_PATH = Path(__file__).resolve().parent / "devices.json"

class DeviceConfigurationError(ValueError):
    pass


def load_devices() -> list[dict]:
    if not DEVICES_PATH.exists():
        raise DeviceConfigurationError(
            f"Brak {DEVICES_PATH.name}; wymagane urządzenia i zakresy sieci"
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
        if not isinstance(host, str) or not host.strip():
            raise DeviceConfigurationError(f"Urządzenie nr {index + 1}: brak host")
        host = host.strip()

        device_type = str(item.get("type", "ssh")).strip().lower()
        if device_type not in ("ssh", "telnet", "none", "local"):
            raise DeviceConfigurationError(
                f"Urządzenie {host}: nieobsługiwany type '{device_type}' (dozwolone: ssh, telnet, local, none)"
            )

        networks = item.get("networks")
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
                    f"Urządzenie {host}: monitoring obsługuje obecnie tylko IPv4"
                )
            parsed_networks.append(parsed)

        name = str(item.get("name") or host)
        base = {
            "name": name,
            "host": host,
            "type": device_type,
            "networks": parsed_networks,
        }

        if device_type in ("none", "local"):
            devices.append(base)
            continue

        username = item.get("username")
        password_env = item.get("password_env")
        arp_command = item.get("arp_command", "display arp" if device_type == "ssh" else "show arp")
        port = item.get("port", 22 if device_type == "ssh" else 23)

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

        base.update({
            "username": username.strip(),
            "password": password,
            "port": port,
            "arp_command": arp_command.strip(),
        })
        if device_type == "telnet":
            logger.warning(
                "%s: type=telnet — połączenie nieszyfrowane, używaj tylko w zaufanej sieci",
                host,
            )
        devices.append(base)

    return devices

MAX_RETRIES = 3
RETRY_DELAY = 2

def get_arp_with_retry(dev: dict) -> set[str] | None:
    name = dev.get("name", dev["host"])
    device_type = dev.get("type", "ssh")

    if device_type == "none":
        logger.info(f"{name} (type=none) → pomijam odczyt ARP")
        return set()

    if device_type == "local":
        logger.info("%s (type=local) → ping klientów, potem lokalne ARP", name)
        clients = database.get_all_clients()
        ips = [c["ip"] for c in clients if c.get("ip")]
        pinged = local_arp.ping_ips(ips)
        arp = local_arp.get_local_arp()
        if arp is None:
            return None
        matched = sum(1 for ip in ips if ip in arp)
        logger.info(
            "%s: spingowano %s, w ARP %s adresów, dopasowano %s klientów",
            name, pinged, len(arp), matched,
        )
        return arp

    port = dev.get("port", 22 if device_type == "ssh" else 23)
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Pobieram ARP z {name} [{device_type}] (próba {attempt}/{MAX_RETRIES})")
            if device_type == "ssh":
                arp = huawei.get_arp_table(
                    host=dev["host"],
                    username=dev["username"],
                    password=dev["password"],
                    port=port,
                    command=dev["arp_command"],
                )
            elif device_type == "telnet":
                arp = telnet_client.get_arp_table(
                    host=dev["host"],
                    username=dev["username"],
                    password=dev["password"],
                    port=port,
                    command=dev["arp_command"],
                )
            else:
                logger.error(f"{name}: nieobsługiwany type {device_type}")
                return None

            if arp is not None:
                logger.info(f"{name} → {len(arp)} wpisów ARP")
                return arp
            else:
                logger.warning(f"{name} → błąd odczytu (próba {attempt})")
        except Exception as e:
            logger.warning(f"{name} → błąd {device_type} (próba {attempt}): {type(e).__name__}: {e}")

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
        active_devices = 0

        for dev in devices:
            if dev.get("type") == "none":
                logger.info("%s: type=none — urządzenie pominięte w odczycie", dev["name"])
                continue

            active_devices += 1
            device_arp = get_arp_with_retry(dev)
            if device_arp is None:
                logger.error("%s: brak wiarygodnego odczytu ARP; odświeżenie anulowane", dev["name"])
                return False
            if not device_arp and dev.get("type") != "local":
                logger.error("%s: pusta tablica ARP; odświeżenie anulowane", dev["name"])
                return False
            reports.append((dev, device_arp or set()))

        if active_devices == 0:
            logger.info("Brak aktywnych urządzeń (tylko type=none) — statusy niezmienione")
            return True

        arp_table: set[str] = set()
        for dev, device_arp in reports:
            arp_table.update(device_arp)

        if not arp_table and not any(dev.get("type") == "local" for dev, _ in reports):
            logger.error("Brak danych ARP; odświeżenie anulowane")
            return False

        logger.info(
            "Zebrano %s adresów ARP z %s urządzeń",
            len(arp_table), active_devices
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
