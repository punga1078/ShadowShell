from flask import Flask, request, make_response, render_template_string
from SRC.logger import Logger
from SRC.notifier import Notifier
import os
import datetime

app = Flask(__name__)
logger = Logger()

# Rutas sensibles que disparan alerta en Telegram
SENSITIVE_PATHS = ['admin', 'login', 'dashboard', 'config', '.env', 'wallet']

# HTML del Login Falso (Parece un panel genérico corporativo)
LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Administration Panel</title>
    <style>
        body { font-family: sans-serif; background-color: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 300px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .error { color: red; font-size: 0.9em; text-align: center; margin-bottom: 10px; display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 style="text-align:center; color:#333;">Admin Portal</h2>
        <div class="error" id="error-msg">Invalid credentials</div>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
    {% if error %}
    <script>document.getElementById('error-msg').style.display = 'block';</script>
    {% endif %}
</body>
</html>
"""

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    # 1. Capturar datos básicos
    ip = request.remote_addr
    method = request.method
    user_agent = request.headers.get('User-Agent', 'Unknown')
    full_path = f"/{path}"
    
    username = ""
    password = ""
    is_auth_attempt = False

    # 2. Lógica de "Honeypot de Credenciales"
    # Si es un POST (envío de formulario), intentamos robar las credenciales
    if method == 'POST':
        username = request.form.get('username') or request.json.get('username') or ""
        password = request.form.get('password') or request.json.get('password') or ""
        if username or password:
            is_auth_attempt = True

    # 3. Preparar el Log
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    
    if is_auth_attempt:
        # LOG ESPECIAL PARA CREDENCIALES
        log_line = f"{timestamp} - [WEB AUTH] IP: {ip} | User: {username} | Pass: {password} | UA: {user_agent}\n"
    else:
        # LOG NORMAL DE TRÁFICO
        log_line = f"{timestamp} - [WEB TRAP] IP: {ip} | Method: {method} | Path: {full_path} | UA: {user_agent}\n"

    # 4. Escribir Log (Con flush y sync)
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = os.path.join(base_dir, 'data', 'access.log')
        
        # print(f"📝 [DEBUG] Escribiendo Auth: {is_auth_attempt}") 

        with open(log_path, "a") as f:
            f.write(log_line)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"❌ [ERROR] {e}")

    # 5. Respuesta al Atacante
    # Si intentó loguearse, le decimos que falló (para que intente otra password)
    if is_auth_attempt:
        return render_template_string(LOGIN_PAGE, error=True), 200
    
    # Si solo está visitando una ruta de login, le mostramos el formulario
    target_paths = ['login', 'admin', 'dashboard', 'signin', 'auth']
    if any(p in full_path.lower() for p in target_paths):
        return render_template_string(LOGIN_PAGE, error=False), 200

    # Para todo lo demás, 403 o 404 falso
    return make_response("<h1>403 Forbidden</h1>", 403)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)