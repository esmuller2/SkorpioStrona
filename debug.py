from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=True)

print("APP_SECRET ustawiony:", bool(os.getenv("APP_SECRET")))
print("ADMIN_PASSWORD_HASH ustawiony:", bool(os.getenv("ADMIN_PASSWORD_HASH")))
print("Długość hasha:", len(os.getenv("ADMIN_PASSWORD_HASH") or ""))