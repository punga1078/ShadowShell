from flask import Flask, request, make_response
from SRC.logger import Logger
from SRC.notifier import Notifier
import os
import datetime

app = Flask(__name__)
logger = Logger()

# Configuración de alertas
SENSITIVE_PATHS = [".env", "config", "admin", "login", "wp-admin", "backup", "shell"]

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    # 1. Capturar datos del atacante
    ip = request.remote_addr
    method = request.method
    user_agent = request.headers.get('User-Agent', 'Unknown')
    full_path = f"/{path}"
    
    # Capturar datos POST si existen (payloads)
    payload = None
    if request.data:
        try:
            payload = request.data.decode('utf-8')[:500] # Limitamos a 500 chars
        except:
            payload = "<binary data>"

    # 2. Guardar en Base de Datos (SQLite)
    logger.log_web(ip, full_path, method, user_agent, payload)

    # 3. Alertas Inteligentes (Telegram - Solo si tocan algo sensible)
    if any(s in full_path.lower() for s in SENSITIVE_PATHS):
        Notifier.send_alert(f"🕸️ *Web Trap Activada*\nIP: `{ip}`\nRuta: `{full_path}`\nUA: `{user_agent}`")

    # 4. [NUEVO] Escribir en log plano para Wazuh
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        log_line = f"{timestamp} - [WEB TRAP] IP: {ip} | Method: {method} | Path: {full_path} | UA: {user_agent}\n"

    # --- CAMBIO CRÍTICO: RUTA ABSOLUTA ---
    # Calcula la ruta exacta donde está este script .py dentro del Docker (/app)
        base_dir = os.path.dirname(os.path.abspath(__file__))
    # Une la ruta base con 'data/access.log' -> /app/data/access.log
        log_path = os.path.join(base_dir, 'data', 'access.log')

    # Imprimir en consola de Docker para confirmar que pasa por aquí
        print(f"📝 [DEBUG] Intentando escribir en: {log_path}") 

        with open(log_path, "a") as f:
            f.write(log_line)
            f.flush()            # Fuerza el vaciado del buffer de Python
            os.fsync(f.fileno()) # Fuerza al sistema operativo a guardar en disco

    except Exception as e:
        print(f"❌ [ERROR] Fallo escribiendo log: {e}")

    # 5. Simulación de Respuesta (Engaño)
    response = make_response("<h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p>", 403)
    response.headers['Server'] = 'nginx/1.18.0'
    return response

if __name__ == '__main__':
    print("🕸️ Iniciando Web Trap en puerto 80...")
    # Escuchar en 0.0.0.0 puerto 80
    app.run(host='0.0.0.0', port=80, debug=False)