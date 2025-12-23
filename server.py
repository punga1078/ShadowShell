import socket
import threading
import paramiko
import time
import logging
import os
import re # Importamos expresiones regulares para extraer URLs
from SRC.shell_emulator import ShellEmulator 
from SRC.logger import Logger
from SRC.notifier import Notifier 
from SRC.vt_scanner import VTScanner 

# Configuración básica de logging
LOG_DIR = 'data'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    format='%(asctime)s - %(message)s',
    level=logging.INFO,
    filename=os.path.join(LOG_DIR, 'access.log')
)

# --- CORRECCIÓN PREVIA: Generador de claves ---
KEY_DIR = 'keys'
KEY_PATH = os.path.join(KEY_DIR, 'server.key')

if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)

if not os.path.exists(KEY_PATH):
    print("🔑 Generando nueva clave RSA de host...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_PATH)

HOST_KEY = paramiko.RSAKey(filename=KEY_PATH)
# ---------------------------------------------

db_logger = Logger()

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip): 
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        db_logger.log_session(self.client_ip, username, password)
        print(f"🎣 [ALERTA] Intento de acceso: {username}:{password}")
        
        Notifier.send_alert(f"🔐 *Acceso Detectado*\nIP: `{self.client_ip}`\nUser: `{username}`\nPass: `{password}`")
        
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
def handle_connection(client_socket, addr):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    server = SSHServer(client_ip=addr[0]) 
    
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        print("❌ Error en la negociación SSH")
        return
    
    chan = transport.accept(20)
    if chan is None:
        print("❌ Nadie se autenticó.")
        return
    
    print(f"✅ ¡INTRUSO DENTRO! {addr}")
    Notifier.send_alert(f"💀 *Shell Abierta*\nEl atacante `{addr[0]}` ha ingresado a la consola.")

    emulator = ShellEmulator()

    chan.send("Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)\r\n\r\n")
    chan.send("Last login: " + time.ctime() + " from 192.168.1.55\r\n")

    while True:
        try:
            prompt = emulator.get_prompt()
            chan.send(prompt)
            
            command = ""
            while True:
                char = chan.recv(1)
                if not char: break 
                if char == b'\r':
                    chan.send(b'\r\n')
                    break
                elif char == b'\x08' or char == b'\x7f':
                    if len(command) > 0:
                        command = command[:-1]
                        chan.send(b'\x08 \x08')
                else:
                    chan.send(char)
                    try:
                        command += char.decode("utf-8")
                    except:
                        pass

            command = command.strip()
            
            if command:
                print(f"💀 [{addr[0]}] Comando: {command}")
                
                # Variable para guardar el resultado de VT (inicialmente vacía)
                vt_analysis_result = None
                
                # --- DETECCIÓN DE AMENAZAS ---
                if "wget" in command or "curl" in command:
                    # Intentamos extraer la URL (buscando http...)
                    url_match = re.search(r'(https?://[^\s]+)', command)
                    
                    vt_report_text = ""
                    if url_match:
                        found_url = url_match.group(1)
                        # Consultamos a VirusTotal
                        vt_report_text = VTScanner.scan_url(found_url)
                        
                        # Limpiamos un poco el texto para guardarlo en la DB sin tanto Markdown
                        vt_analysis_result = vt_report_text.replace("**", "").replace("🔗", "")
                    
                    Notifier.send_alert(f"⚠️ *Actividad Maliciosa*\nIP: `{addr[0]}`\nCmd: `{command}`\n\n🛡️ *Análisis VT:*\n{vt_report_text}")
                
                elif "sudo" in command:
                     Notifier.send_alert(f"⚠️ *Intento de Root*\nIP: `{addr[0]}`\nCmd: `{command}`")

                # --- GUARDADO EN BASE DE DATOS ---
                # Ahora pasamos el resultado (sea None o texto) AL FINAL del proceso
                db_logger.log_command(addr[0], command, vt_result=vt_analysis_result)

            if command == "exit":
                chan.send("Logout.\r\n")
                break
            
            response = emulator.execute(command)
            chan.send(response)

        except Exception as e:
            print(f"⚠️ Conexión perdida: {e}")
            break

    chan.close()

def start_honeypot(port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(100)

    print(f"🕸️ ShadowShell iniciado en el puerto {port}...")
    Notifier.send_alert("🟢 **ShadowShell Iniciado**\nEsperando víctimas...")
    
    while True:
        client, addr = sock.accept()
        print(f"🔗 Conexión entrante de: {addr[0]}")
        client_handler = threading.Thread(target=handle_connection, args=(client, addr))
        client_handler.start()

if __name__ == "__main__":
    start_honeypot()