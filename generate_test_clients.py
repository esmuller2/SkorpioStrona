#!/usr/bin/env python3
"""Generator klientów testowych. Używa osobnej bazy testowej."""

import sqlite3
from pathlib import Path

TEST_DB = Path(__file__).resolve().parent / "clients_test.sqlite3"

def main():
    print(f"Generuję klientów testowych do: {TEST_DB}")
    print("To NIE jest produkcyjna baza (clients.sqlite3).")

    confirm = input("Kontynuować? (tak/nie): ").strip().lower()
    if confirm not in ("tak", "t", "yes", "y"):
        print("Anulowano.")
        return

    conn = sqlite3.connect(TEST_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ok',
            error_time TEXT,
            ping_ms INTEGER,
            last_seen TEXT
        )
    """)
    conn.execute("DELETE FROM clients")

    for i in range(1, 1001):
        client_id = f"TEST-{i:04d}"
        # Rozkład po kilku podsieciach
        if i <= 250:
            ip = f"192.168.1.{i % 254 + 1}"
        elif i <= 500:
            ip = f"192.168.0.{i % 254 + 1}"
        elif i <= 750:
            ip = f"192.168.2.{i % 254 + 1}"
        else:
            ip = f"192.168.3.{i % 254 + 1}"
        conn.execute(
            "INSERT INTO clients (client_id, ip, status) VALUES (?, ?, 'ok')",
            (client_id, ip)
        )

    conn.commit()
    conn.close()
    print(f"Dodano 1000 klientów testowych do {TEST_DB}")

if __name__ == "__main__":
    main()