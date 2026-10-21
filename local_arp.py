import subprocess
import platform
import re
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def ping_ips(ips: list[str], timeout_ms: int = 800, max_workers: int = 12) -> int:
    """Pinguje listę adresów IPv4. Zwraca liczbę uruchomionych pingów."""
    unique = []
    seen = set()
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            unique.append(ip)
    if not unique:
        logger.info("Brak klientów do pingowania")
        return 0

    system = platform.system().lower()
    timeout_sec = max(1, timeout_ms // 1000)

    def _ping_one(ip: str) -> None:
        try:
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_sec + 2,
            )
        except Exception:
            pass

    logger.info("Pinguję %s klientów (równolegle do %s)...", len(unique), max_workers)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_ping_one, ip) for ip in unique]
        for _ in as_completed(futures):
            pass
    logger.info("Ping zakończony (%s adresów)", len(unique))
    return len(unique)

def get_local_arp() -> set[str] | None:
    """Odczytuje lokalną tablicę ARP systemu (Windows: arp -a, Linux/macOS: arp -n)."""
    try:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["arp", "-a"]
        else:
            cmd = ["arp", "-n"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            logger.error("Lokalny ARP zwrócił błąd: %s", result.stderr.strip())
            return None

        arp: set[str] = set()
        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        for line in result.stdout.splitlines():
            for match in ip_re.finditer(line):
                ip = match.group(1)
                try:
                    address = ipaddress.IPv4Address(ip)
                except ipaddress.AddressValueError:
                    continue
                if address.is_multicast or address.is_unspecified or address.is_loopback:
                    continue
                if str(address).endswith(".255"):
                    continue
                arp.add(str(address))

        logger.info("Lokalny ARP: %s adresów", len(arp))
        return arp
    except Exception as e:
        logger.error("Błąd lokalnego ARP: %s: %s", type(e).__name__, e)
        return None