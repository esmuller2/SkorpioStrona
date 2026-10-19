from dotenv import load_dotenv
import os
import bcrypt

load_dotenv()
h = os.getenv("ADMIN_PASSWORD_HASH")

print("HASH:", repr(h))
print("DLUGOSC:", len(h) if h else 0)
print("ZACZYNA SIE OD $2b$:", h.startswith("$2b$") if h else False)

if h:
    try:
        ok = bcrypt.checkpw(b"admin123", h.encode())
        print("HASLO admin123 DZIALA:", ok)
    except Exception as e:
        print("BLAD:", e)
else:
    print("BRAK HASHA")