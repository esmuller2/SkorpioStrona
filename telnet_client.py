import telnetlib
import logging
import ipaddress
import time

logger = logging.getLogger(__name__)

def get_arp_table(
    host: str,
    username: str,
    password: str,
    port: int = 23,
    command: str = "show arp",
    login_prompt: bytes = b"login: ",
    password_prompt: bytes = b"Password: ",
) -> set[str] | None:
    """Zwraca IPv4 z tablicy ARP przez Telnet albo None przy błędzie."""
    tn = None
    try:
        tn = telnetlib.Telnet(host, port, timeout=10)
        tn.read_until(login_prompt, timeout=8)
        tn.write(username.encode("ascii") + b"\n")
        tn.read_until(password_prompt, timeout=8)
        tn.write(password.encode("ascii") + b"\n")
        time.sleep(0.5)
        tn.write(command.encode("ascii") + b"\n")
        time.sleep(1.5)
        output = tn.read_very_eager().decode(errors="ignore")

        arp: set[str] = set()
        for line in output.splitlines():
            parts = line.split()
            for part in parts:
                try:
                    address = ipaddress.IPv4Address(part)
                except ipaddress.AddressValueError:
                    continue
                if not address.is_multicast and not address.is_unspecified:
                    arp.add(str(address))
        return arp
    except Exception as e:
        logger.error(f"Telnet {host}:{port}: {type(e).__name__}: {e}")
        return None
    finally:
        if tn is not None:
            try:
                tn.close()
            except Exception:
                pass
