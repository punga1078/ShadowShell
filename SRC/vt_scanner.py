import requests
import os
import base64
from dotenv import load_dotenv

# Cargar variables de entorno
current_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.dirname(current_dir)
env_path = os.path.join(base_dir, '.env')
load_dotenv(env_path)

VT_API_KEY = os.getenv("VT_API_KEY")

class VTScanner:
    @staticmethod
    def scan_url(target_url):
        """
        Consulta la reputación de una URL en VirusTotal sin descargar el archivo.
        Retorna un resumen de texto.
        """
        if not VT_API_KEY:
            return "⚠️ Falta API Key de VirusTotal"

        print(f"🔎 Consultando VirusTotal para: {target_url}")

        # 1. Codificar la URL en Base64 (Requisito de la API de VT)
        # VirusTotal requiere que la URL esté codificada en base64 sin el relleno '='
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": VT_API_KEY
        }

        try:
            response = requests.get(api_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats['malicious']
                suspicious = stats['suspicious']
                
                # Generamos el enlace directo al reporte visual
                gui_link = f"https://www.virustotal.com/gui/url/{url_id}/detection"
                
                if malicious > 0:
                    return f"☣️ **¡PELIGRO!** Detectado por {malicious} antivirus.\n🔗 [Ver Reporte]({gui_link})"
                else:
                    return f"✅ **Limpio** (o desconocido).\n🔗 [Ver Reporte]({gui_link})"
            
            elif response.status_code == 404:
                return "ℹ️ URL no analizada previamente por VirusTotal."
            
            elif response.status_code == 401:
                return "⚠️ Error de API Key (Verifica tu .env)."
            
            else:
                return f"⚠️ Error VT: Código {response.status_code}"

        except Exception as e:
            return f"⚠️ Error de conexión con VT: {e}"

# Prueba rápida si ejecutas este archivo directamente
if __name__ == "__main__":
    test_url = "http://google.com"
    print(VTScanner.scan_url(test_url))