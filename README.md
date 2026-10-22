# LAN Clients Monitor

Lokalna aplikacja FastAPI do ewidencji klientów IPv4, odczytu tablic ARP urządzeń (SSH / Telnet) i raportowania awarii.

## Wymagania

- Python 3.10 lub nowszy.
- Dla urządzeń `type: "ssh"`: dostęp SSH oraz konto z prawem wykonania skonfigurowanej komendy ARP.
- Dla urządzeń `type: "telnet"`: dostęp Telnet. **Uwaga:** Telnet jest nieszyfrowany — używaj tylko w zaufanej sieci lokalnej.
- Urządzenia `type: "none"` są pomijane (np. gdy nie chcesz ich odpytywać).
- Urządzenia `type: "local"` używają pingu klientów z bazy i lokalnej tablicy ARP systemu.
- Zaufane klucze SSH zapisane w systemowym `known_hosts` albo w pliku `known_hosts` w katalogu projektu.
- Na produkcji ustaw `HTTPS_ONLY=true`. Opcjonalnie `SESSION_MAX_AGE` (sekundy, domyślnie 8 godzin).

## Instalacja i uruchomienie

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item devices.example.json devices.json
```

Utwórz `.env` z losowym `APP_SECRET`, hashem bcrypt w `ADMIN_PASSWORD_HASH` oraz `USER_PASSWORD_HASH`. Konta:

- `admin` — pełny dostęp (dodawanie, edycja, usuwanie, backup, czyszczenie)
- `uzytkownik` — tylko podgląd listy, historii i raportu nocnego

Hash użytkownika generujesz tak:

```powershell
python -c "import bcrypt; print(bcrypt.hashpw(b'TWOJE_HASLO', bcrypt.gensalt()).decode())"
```

Uruchom pojedynczy proces:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Scheduler działa wewnątrz procesu aplikacji; uruchomienie wielu workerów uruchomi wielokrotnie monitoring i zadania backupu. Dla dostępu przez HTTPS ustaw `HTTPS_ONLY=true` i skonfiguruj TLS na serwerze/proxy. Nie wystawiaj aplikacji bezpośrednio do Internetu bez HTTPS i ograniczenia dostępu.

## Monitoring

- Odczyt statusów wykonywany jest od razu po starcie, a następnie co 30 sekund.
- Monitor korzysta z urządzeń i zakresów podanych w `devices.json`.
- `type: "ssh"` — odczyt przez Paramiko (domyślnie).
- `type: "telnet"` — odczyt przez Telnet.
- `type: "none"` — urządzenie jest pomijane (nie przerywa odświeżania).
- Dla aktywnych urządzeń `arp_command` określa komendę wyświetlającą tablicę ARP. Brak pliku, brak sekretu, niedostępne urządzenie, pusta tablica ARP albo brak potwierdzonego pokrycia podsieci powoduje pominięcie całego odświeżenia. Nie są wtedy zmieniane statusy klientów.
- Wpis `networks` deklaruje podsieć widoczną z danego urządzenia. Każdy adres klienta musi być IPv4 i należeć do co najmniej jednej podsieci, dla której odczyt ARP zawiera wpis. To ogranicza fałszywe awarie, ale nie gwarantuje wykrycia urządzeń, które nie pojawiają się w tablicy ARP.
- Przy nieudanym ręcznym odświeżeniu interfejs pokazuje błąd; dokładna przyczyna jest logowana w terminalu.

## Dane i kopie zapasowe

- Baza aplikacji: `clients.sqlite3`.
- Backupy: `backups/`, maksymalnie 14 najnowszych kopii.
- Generator danych testowych zapisuje wyłącznie do `clients_test.sqlite3`.
- Historia awarii jest zachowywana po usunięciu klienta; otwarty wpis zostaje zamknięty.
- Nie publikuj `.env`, baz, backupów, `devices.json` ani `known_hosts`.

## Uruchomienie testów

```powershell
python -m unittest discover -s tests -v
```

Ograniczanie prób logowania jest przechowywane w pamięci procesu. Przy wielu instancjach lub reverse proxy potrzebny jest zewnętrzny, współdzielony limiter; nie ufaj bez konfiguracji nagłówkom `X-Forwarded-For`.
