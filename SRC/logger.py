import sqlite3
import os

class Logger:
    def __init__(self, db_path="data/interacciones.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 1. Crear tabla COMMANDS (si no existe)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                command TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                vt_result TEXT  -- Nueva columna para el reporte
            )
        ''')

        # --- MIGRACIÓN AUTOMÁTICA ---
        # Si la tabla ya existía de antes, intentamos agregar la columna 'vt_result'
        # Si ya existe, dará error y lo ignoramos (pass)
        try:
            cursor.execute("ALTER TABLE commands ADD COLUMN vt_result TEXT")
        except sqlite3.OperationalError:
            pass # La columna ya existe, todo en orden
        # ----------------------------

        # 2. Crear tabla SESSIONS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                username TEXT,
                password TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def log_session(self, ip, username, password):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO sessions (ip, username, password) VALUES (?, ?, ?)", 
                           (ip, username, password))
            conn.commit()
            conn.close()
            print(f"💾 [DB] Sesión guardada: {username}@{ip}")
        except Exception as e:
            print(f"⚠️ Error DB Sesión: {e}")

    # --- MODIFICADO: Ahora acepta vt_result opcional ---
    def log_command(self, ip, command, vt_result=None):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO commands (ip, command, vt_result) VALUES (?, ?, ?)", 
                           (ip, command, vt_result))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"⚠️ Error DB Comando: {e}")