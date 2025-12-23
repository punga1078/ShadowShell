import requests
import threading
import os
from dotenv import load_dotenv


current_dir = os.path.dirname(os.path.abspath(__file__))

base_dir = os.path.dirname(current_dir)

env_path = os.path.join(base_dir, '.env')

load_dotenv(env_path)

print(f"📂 Buscando .env en: {env_path}")
print(f"🔑 Token cargado: {'SÍ' if os.getenv('TELEGRAM_TOKEN') else 'NO'}")

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

class Notifier:
    # ... (El resto del código sigue igual) ...
    @staticmethod
    def send_alert(message):
        if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            print("⚠️ Advertencia: Credenciales vacías. Revisa tu archivo .env")
            return

        thread = threading.Thread(target=Notifier._send_request, args=(message,))
        thread.start()

    @staticmethod
    def _send_request(message):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            data = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": f"🚨 [ShadowShell Alert]\n{message}",
                "parse_mode": "Markdown"
            }
            requests.post(url, data=data, timeout=5)
        except Exception as e:
            print(f"⚠️ Error enviando alerta a Telegram: {e}")