import paramiko
import logging
import ipaddress
from pathlib import Path

logger = logging.getLogger(__name__)
KNOWN_HOSTS = Path(__file__).resolve().parent / "known_hosts"

def get_arp_table(host: str, username: str, password: str, port: int = 22) -> set[str] | None:
    """Zwraca IPv4 z tablicy ARP albo None, jeśli połączenie/odczyt się nie powiódł."""
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
        if KNOWN_HOSTS.exists():
            client.load_host_keys(str(KNOWN_HOSTS))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
        stdin, stdout, stderr = client.exec_command("display arp", timeout=15)
        stdout.channel.set_combine_stderr(True)
        output = stdout.read().decode(errors="ignore")
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            logger.error(f"SSH {host}: polecenie zakończone kodem {exit_status}")
            return None

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
        logger.error(f"SSH {host}: {type(e).__name__}: {e}")
        return None
    finally:
        client.close()