import subprocess
import platform
import re
import logging
import ipaddress

logger = logging.getLogger(__name__)

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
