import socket
import logging
import ipaddress
import time

logger = logging.getLogger(__name__)

def _recv_until(sock: socket.socket, marker: bytes, timeout: float = 8.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if marker in data:
                break
        except socket.timeout:
            break
    return data

def get_arp_table(
    host: str,
    username: str,
    password: str,
    port: int = 23,
    command: str = "show arp",
    login_prompt: bytes = b"login:",
    password_prompt: bytes = b"Password:",
) -> set[str] | None:
    """Zwraca IPv4 z tablicy ARP przez Telnet albo None przy błędzie.
    Implementacja na czystych socketach (działa na Python 3.13+).
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.settimeout(8)

        _recv_until(sock, login_prompt, timeout=8)
        sock.sendall(username.encode("ascii", errors="ignore") + b"\r\n")

        _recv_until(sock, password_prompt, timeout=8)
        sock.sendall(password.encode("ascii", errors="ignore") + b"\r\n")

        time.sleep(0.6)
        sock.sendall(command.encode("ascii", errors="ignore") + b"\r\n")
        time.sleep(1.8)

        output = b""
        sock.settimeout(2.0)
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                output += chunk
        except socket.timeout:
            pass

        text = output.decode(errors="ignore")
        arp: set[str] = set()
        for line in text.splitlines():
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
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
