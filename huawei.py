import paramiko
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def _ssh_command(host: str, username: str, password: str, command: str, timeout: int = 10) -> str:
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="ignore").strip()
        return output
    except Exception as e:
        logger.error(f"SSH error na {host}: {type(e).__name__}")
        return ""
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

def get_arp_table(host: str, username: str, password: str) -> list[dict]:
    output = _ssh_command(host, username, password, "display arp")
    if not output:
        return []

    entries = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].count(".") == 3:
            ip = parts[0]
            mac = parts[1] if len(parts) > 1 else ""
            entries.append({"ip": ip, "mac": mac})
    return entries

def check_client_in_arp(host: str, username: str, password: str, client_ip: str) -> bool:
    arp = get_arp_table(host, username, password)
    return any(entry["ip"] == client_ip for entry in arp)