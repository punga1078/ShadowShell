from flask import Flask, request, make_response
from SRC.logger import Logger
from SRC.notifier import Notifier
import os

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

    # 2. Guardar en Base de Datos
    logger.log_web(ip, full_path, method, user_agent, payload)

    # 3. Alertas Inteligentes (Solo si tocan algo sensible)
    if any(s in full_path.lower() for s in SENSITIVE_PATHS):
        Notifier.send_alert(f"🕸️ *Web Trap Activada*\nIP: `{ip}`\nRuta: `{full_path}`\nUA: `{user_agent}`")

    # 4. Simulación de Respuesta (Engaño)
    # A veces devolvemos 403 (Prohibido) para que intenten más, 
    # o 200 con un login falso si quieres mejorar esto luego.
    # Por ahora, simulamos un servidor Nginx genérico.
    response = make_response("<h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p>", 403)
    response.headers['Server'] = 'nginx/1.18.0'
    return response

if __name__ == '__main__':
    print("🕸️ Iniciando Web Trap en puerto 80...")
    # Escuchar en 0.0.0.0 puerto 80
    app.run(host='0.0.0.0', port=80, debug=False)