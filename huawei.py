import paramiko
import logging

logger = logging.getLogger(__name__)

def get_arp_table(host: str, username: str, password: str, port: int = 22) -> set[str] | None:
    """Zwraca zbiór IP lub None przy błędzie. Pusta tabela to poprawny wynik."""
    try:
        client = paramiko.SSHClient()
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
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore").strip()
        client.close()

        if exit_status != 0:
            logger.error(f"SSH {host}: polecenie zakończone kodem {exit_status}")
            return None
        if err and ("error" in err.lower() or "fail" in err.lower()):
            logger.error(f"SSH {host}: stderr: {err[:300]}")
            return None

        arp: set[str] = set()
        for line in output.splitlines():
            parts = line.split()
            for part in parts:
                if part.count(".") == 3:
                    try:
                        octets = part.split(".")
                        if all(0 <= int(o) <= 255 for o in octets):
                            if not part.endswith(".255") and not part.startswith("224."):
                                arp.add(part)
                    except ValueError:
                        continue
        return arp
    except Exception as e:
        logger.error(f"SSH {host}: {type(e).__name__}: {e}")
        return None