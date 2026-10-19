import paramiko
import logging

logger = logging.getLogger(__name__)

def _ssh_command(host: str, username: str, password: str, command: str, timeout: int = 10, port: int = 22) -> str:
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="ignore").strip()
        err = stderr.read().decode("utf-8", errors="ignore").strip()
        if err:
            logger.warning(f"SSH stderr na {host}:{port}: {err}")
        return output
    except Exception as e:
        logger.error(f"SSH error na {host}:{port}: {type(e).__name__}: {e}")
        return ""
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

def get_arp_table(host: str, username: str, password: str, port: int = 22) -> set[str]:
    """Zwraca zbiór IP z tablicy ARP urządzenia."""
    output = _ssh_command(host, username, password, "display arp", port=port)
    if not output:
        return set()

    ips = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].count(".") == 3:
            ip = parts[0]
            if not ip.endswith(".255") and not ip.startswith("224."):
                ips.add(ip)
    return ips

def check_client_in_arp(host: str, username: str, password: str, client_ip: str, port: int = 22) -> bool:
    arp = get_arp_table(host, username, password, port=port)
    return client_ip in arp