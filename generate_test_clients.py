import database
import random

def generate():
    database.init_db()
    
    # Czyścimy starą bazę (opcjonalnie — usuń tę linię jeśli chcesz dodać do istniejących)
    with database.get_db() as conn:
        conn.execute("DELETE FROM clients")
    
    print("Generuję 500 klientów testowych...")
    
    for i in range(1, 501):
        client_id = f"TEST-{i:03d}"
        # Generujemy adresy z zakresu 10.0.0.0/16 i 192.168.0.0/16
        if i % 2 == 0:
            ip = f"10.{random.randint(0, 50)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            ip = f"192.168.{random.randint(0, 50)}.{random.randint(1, 254)}"
        
        # Część będzie "martwa" (nieistniejące IP), część może odpowiadać
        database.add_client(client_id, ip, "ok")
        
        if i % 100 == 0:
            print(f"Dodano {i}/500")
    
    print("Gotowe! Dodano 500 klientów testowych.")

if __name__ == "__main__":
    generate()