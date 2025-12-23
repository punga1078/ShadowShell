import sqlite3

conn = sqlite3.connect("DATA/interacciones.db")
cursor = conn.cursor()

print("--- 🔐 CREDENCIALES CAPTURADAS ---")
for row in cursor.execute("SELECT * FROM sessions"):
    print(row)

print("\n--- 💀 COMANDOS EJECUTADOS ---")
for row in cursor.execute("SELECT * FROM commands"):
    print(row)

conn.close()