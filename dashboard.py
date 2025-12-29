import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import requests
import os
import time
import json
from streamlit_autorefresh import st_autorefresh
import random
# --- NUEVAS LIBRERÍAS PARA PDF ---
from fpdf import FPDF
from datetime import datetime

# ==========================================
# 🔐 SISTEMA DE LOGIN (VERSIÓN ROBUSTA)
# ==========================================
def check_password():
    """Retorna True si el usuario ingresó la contraseña correcta."""
    
    # 1. Obtener contraseña segura del entorno
    CORRECT_PASSWORD = os.getenv("DASHBOARD_PASSWORD")
    
    # 2. Si no hay contraseña en el .env, BLOQUEAR ACCESO por seguridad
    if not CORRECT_PASSWORD:
        st.error("⚠️ ERROR CRÍTICO DE SEGURIDAD: No se ha configurado DASHBOARD_PASSWORD en el archivo .env")
        st.stop()

    # 3. Inicializar estado de sesión si no existe
    if "password_correct" not in st.session_state:
        st.session_state.password_correct = False

    # 4. Si ya está logueado, salir de la función y permitir carga del dashboard
    if st.session_state.password_correct:
        return

    # 5. Interfaz de Login
    st.set_page_config(page_title="ShadowShell Login", page_icon="🔐")
    
    st.markdown(
        """
        <style>
        .stApp {align-items: center; justify-content: center;}
        </style>
        """,
        unsafe_allow_html=True
    )
    
    st.title("🛡️ ShadowShell Access")
    st.markdown("---")
    
    # Input de contraseña sin callback complejo
    password_input = st.text_input("Ingrese la clave de acceso:", type="password")

    # 6. Validación Directa
    if password_input:
        if password_input == CORRECT_PASSWORD:
            st.session_state.password_correct = True
            st.rerun()  # Recarga inmediata para limpiar la pantalla de login
        else:
            st.error("⛔ Contraseña incorrecta. Intente nuevamente.")

    # ⛔ DETENER EJECUCIÓN AQUÍ SI NO ESTÁ LOGUEADO
    st.stop()

# Ejecutar el check antes de cualquier otra cosa
check_password()

# ==========================================
# 📄 MOTOR DE REPORTES PDF (NUEVO)
# ==========================================
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'ShadowShell - Informe de Inteligencia de Amenazas', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Generado el: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

def create_pdf(df_sess, df_cmds, risk_score):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # 1. Resumen Ejecutivo
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "1. Resumen Ejecutivo", 0, 1)
    pdf.set_font("Arial", size=11)
    
    total_attacks = len(df_sess)
    unique_ips = df_sess['ip'].nunique() if not df_sess.empty else 0
    total_cmds = len(df_cmds)
    
    pdf.cell(0, 8, f"- Total de Intrusiones Detectadas: {total_attacks}", 0, 1)
    pdf.cell(0, 8, f"- Atacantes Unicos: {unique_ips}", 0, 1)
    pdf.cell(0, 8, f"- Comandos Capturados: {total_cmds}", 0, 1)
    pdf.cell(0, 8, f"- Nivel de Riesgo Promedio (AbuseIPDB): {risk_score:.1f}%", 0, 1)
    pdf.ln(5)

    # 2. Top Atacantes
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "2. Top 5 Direcciones IP Hostiles", 0, 1)
    pdf.set_font("Arial", size=10)
    
    # Cabecera de tabla
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(50, 8, "Direccion IP", 1, 0, 'C', 1)
    pdf.cell(40, 8, "Intentos", 1, 0, 'C', 1)
    pdf.cell(60, 8, "Usuario mas usado", 1, 1, 'C', 1)
    
    if not df_sess.empty:
        top_ips = df_sess['ip'].value_counts().head(5)
        for ip, count in top_ips.items():
            # Buscar usuario más usado por esta IP
            try:
                top_user = df_sess[df_sess['ip'] == ip]['username'].mode()[0]
            except:
                top_user = "Unknown"
            pdf.cell(50, 8, str(ip), 1)
            pdf.cell(40, 8, str(count), 1, 0, 'C')
            pdf.cell(60, 8, str(top_user), 1, 1)
    else:
        pdf.cell(0, 8, "Sin datos suficientes.", 1, 1)
    pdf.ln(5)

    # 3. Comandos Críticos
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "3. Evidencia Forense (Ultimos Comandos Criticos)", 0, 1)
    pdf.set_font("Courier", size=9) # Fuente tipo consola
    
    if not df_cmds.empty:
        # Filtramos comandos interesantes
        crits = df_cmds[df_cmds['command'].str.contains("wget|curl|sudo|rm|cat", case=False)].head(10)
        if crits.empty:
            crits = df_cmds.head(5)
            
        for idx, row in crits.iterrows():
            clean_cmd = str(row['command'])[:60] # Cortar si es muy largo
            # Evitar caracteres que rompan PDF
            clean_cmd = clean_cmd.encode('latin-1', 'replace').decode('latin-1')
            pdf.cell(0, 6, f"[{row['timestamp']}] {row['ip']} $ {clean_cmd}", 0, 1)
    else:
        pdf.cell(0, 8, "Sin comandos registrados.", 0, 1)

    return pdf.output(dest='S').encode('latin-1', 'replace')

# ==========================================
# 🚀 INICIO DEL DASHBOARD REAL
# ==========================================

st.set_page_config(
    page_title="ShadowShell | CTI",
    page_icon="🕵️‍♂️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Refresco automático cada 10 segundos (para dar tiempo a la API)
count = st_autorefresh(interval=10000, limit=None, key="fizzbuzzcounter") 
st.title("🕵️‍♂️ ShadowShell - Threat Intelligence Dashboard")
st.caption("Monitor de Amenazas SSH + Enriquecimiento con AbuseIPDB")
st.markdown("---")

# --- FUNCIÓN DE CARGA DE DATOS ---
def load_data():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, 'data', 'interacciones.db')
        
        if not os.path.exists(db_path):
            return pd.DataFrame(), pd.DataFrame()

        conn = sqlite3.connect(db_path)
        df_sessions = pd.read_sql_query("SELECT * FROM sessions ORDER BY timestamp DESC", conn)
        df_commands = pd.read_sql_query("SELECT * FROM commands ORDER BY timestamp DESC", conn)
        conn.close()
        return df_sessions, df_commands
    except Exception as e:
        st.error(f"Error DB: {e}")
        return pd.DataFrame(), pd.DataFrame()

# --- NUEVO: CONSULTA A ABUSEIPDB (Con Caché Inteligente) ---
@st.cache_data(show_spinner=False, ttl=3600*24) # Guardar en caché por 24hs
def check_abuseipdb(ip):
    """Consulta la reputación de una IP en AbuseIPDB"""
    
    # Ignorar IPs privadas
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return {"score": 0, "usage": "Private/Local", "domain": "Localhost", "country": "Local"}

    api_key = os.getenv("ABUSEIPDB_KEY")
    if not api_key:
        return {"score": -1, "usage": "No API Key", "domain": "Unknown", "country": "?"}

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}

    try:
        # Pequeña pausa para no romper límites de API gratis
        time.sleep(0.5)
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "score": data.get('abuseConfidenceScore', 0),
                "usage": data.get('usageType', 'Unknown'),
                "domain": data.get('domain', 'Unknown'),
                "country": data.get('countryCode', 'Unknown')
            }
        else:
            return {"score": -1, "usage": "API Error", "domain": "Unknown", "country": "?"}
    except:
        return {"score": -1, "usage": "Conn Error", "domain": "Unknown", "country": "?"}

# --- FUNCIÓN MITRE ATT&CK ---
def map_mitre_tactic(command):
    cmd = command.lower()
    if "wget" in cmd or "curl" in cmd: return "Resource Development (T1588)"
    elif "rm " in cmd or "history -c" in cmd: return "Defense Evasion (T1070)"
    elif "cat /etc/shadow" in cmd or "cat passwords" in cmd: return "Credential Access (T1003)"
    elif "sudo" in cmd or "su " in cmd: return "Privilege Escalation (T1068)"
    elif "ls" in cmd or "ps" in cmd or "whoami" in cmd: return "Discovery (T1082)"
    elif "./" in cmd or "python" in cmd or "bash" in cmd: return "Execution (T1059)"
    else: return "Uncategorized"

# --- GEOLOCALIZACIÓN OPTIMIZADA ---
@st.cache_data(show_spinner=False)
def get_single_ip_data(ip):
    if ip == "localhost" or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        fake_locations = [
            {'lat': 55.7558, 'lon': 37.6173, 'city': 'Moscow', 'country': 'Russia'},
            {'lat': 39.9042, 'lon': 116.4074, 'city': 'Beijing', 'country': 'China'},
            {'lat': -23.5505, 'lon': -46.6333, 'city': 'Sao Paulo', 'country': 'Brazil'}
        ]
        random.seed(ip)
        fake = random.choice(fake_locations)
        return {'ip': ip, 'lat': fake['lat'], 'lon': fake['lon'], 'city': f"{fake['city']} (Sim)", 'country': fake['country'], 'isp': 'Private', 'org': 'Private'}

    try:
        time.sleep(1.1) 
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if response['status'] == 'success':
            return {'ip': ip, 'lat': response['lat'], 'lon': response['lon'], 'city': response['city'], 
                    'country': response['country'], 'isp': response['isp'], 'org': response.get('org', 'Unknown')}
        else: return None
    except: return None

def get_geolocation(ip_list):
    locations = []
    if len(ip_list) > 0:
        my_bar = st.progress(0, text="Geolocalizando atacantes...")
    for i, ip in enumerate(ip_list):
        data = get_single_ip_data(ip)
        if data: locations.append(data)
        if len(ip_list) > 0: my_bar.progress((i + 1) / len(ip_list))
    if len(ip_list) > 0: my_bar.empty()
    return pd.DataFrame(locations) if locations else pd.DataFrame(columns=['lat', 'lon', 'city', 'country', 'isp', 'org'])

# Cargar datos
df_sessions, df_commands = load_data()

# --- SISTEMA DE DETECCIÓN DE AMENAZAS (IDS) ---
st.subheader("🛡️ Monitor de Seguridad")

honeyfiles = ["passwords.txt", "wallet_backup.json", "clientes_2025.csv"]
dangerous_cmds = ["wget", "curl", "sudo", "rm -rf"] 
all_patterns = honeyfiles + dangerous_cmds

if not df_commands.empty:
    search_pattern = '|'.join(all_patterns)
    threats = df_commands[df_commands['command'].str.contains(search_pattern, case=False, na=False)]
    
    if not threats.empty:
        st.error(f"🚨 ALERTA CRÍTICA: ¡{len(threats)} acciones hostiles detectadas!")
        with st.expander("Ver Detalles del Incidente (Forensics)", expanded=True):
            st.dataframe(threats[['timestamp', 'ip', 'command']], use_container_width=True)
    else:
        st.success("✅ Sistema Seguro: Sin actividad crítica reciente.")
else:
    st.info("Esperando datos...")

st.markdown("---")

# Botón de refresco
if st.button('🔄 Refrescar Datos'):
    st.rerun()

# --- KPIs ---
col1, col2, col3, col4 = st.columns(4)
with col1: st.metric("Intrusiones Totales", len(df_sessions))
with col2: st.metric("Atacantes Únicos", df_sessions['ip'].nunique() if not df_sessions.empty else 0)
with col3: st.metric("Comandos EXEC/Shell", len(df_commands))

# KPI DE RIESGO (Nuevo)
avg_risk = 0
if not df_sessions.empty:
    sample_ips = df_sessions['ip'].unique()[:5] # Muestra rápida
    total_score = 0
    valid_samples = 0
    for ip in sample_ips:
        res = check_abuseipdb(ip)
        if res['score'] >= 0:
            total_score += res['score']
            valid_samples += 1
    if valid_samples > 0:
        avg_risk = total_score / valid_samples
    
with col4: 
    st.metric("Nivel de Amenaza (Avg)", f"{avg_risk:.1f}%", delta="Abuse Score Promedio", delta_color="inverse")

# =========================================================
#  NUEVO: SECCIÓN DE INTELIGENCIA DE AMENAZAS (CTI)
# =========================================================
st.markdown("---")
st.subheader("🧬 Análisis de Inteligencia (AbuseIPDB)")
st.caption("Verificación de reputación criminal en tiempo real de los Top 10 atacantes.")

if not df_sessions.empty:
    unique_attackers = df_sessions['ip'].value_counts().reset_index()
    unique_attackers.columns = ['IP', 'Intentos']
    
    reputation_data = []
    
    # Analizamos Top 10 para no saturar API
    for index, row in unique_attackers.head(10).iterrows():
        ip = row['IP']
        intel = check_abuseipdb(ip)
        reputation_data.append({
            "IP": ip,
            "Intentos": row['Intentos'],
            "Riesgo (0-100)": intel['score'],
            "Uso": intel['usage'],
            "Dominio": intel['domain'],
            "País": intel['country']
        })
    
    df_rep = pd.DataFrame(reputation_data)
    
    # Función para colorear filas peligrosas
    def color_risk(val):
        color = '#0e1117' # default
        if isinstance(val, int):
            if val > 75: color = '#5a0000' # Rojo Oscuro (Peligro Extremo)
            elif val > 50: color = '#5a3a00' # Naranja Oscuro (Peligro)
        return f'background-color: {color}'

    st.dataframe(
        df_rep.style.background_gradient(subset=['Riesgo (0-100)'], cmap='Reds', vmin=0, vmax=100),
        use_container_width=True
    )
else:
    st.info("Esperando atacantes para analizar reputación...")

# =========================================================
#  TABLAS DE LOGS DETALLADOS
# =========================================================
st.markdown("---")
col_logins, col_cmds = st.columns(2)

with col_logins:
    st.subheader("🕵️ Últimos Logins")
    if not df_sessions.empty:
        st.dataframe(df_sessions[['timestamp', 'ip', 'username', 'password']], hide_index=True, use_container_width=True)
    else:
        st.info("Sin registros.")

with col_cmds:
    st.subheader("⌨️ Comandos Ejecutados")
    if not df_commands.empty:
        cols_cmd = ['timestamp', 'ip', 'command']
        if 'vt_result' in df_commands.columns:
            cols_cmd.append('vt_result')
        st.dataframe(df_commands[cols_cmd], hide_index=True, use_container_width=True)
    else:
        st.info("Sin comandos.")

st.markdown("---")

# --- PESTAÑAS PRINCIPALES ---
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🗺️ Mapa de Amenazas", "💀 Actividad en Vivo", "🦠 Malware", 
    "🔐 Credenciales", "📊 Gráficos", "🛡️ MITRE ATT&CK" 
])

# PESTAÑA 1: MAPA
with tab1:
    st.subheader("🌍 Origen de los Ataques")
    if not df_sessions.empty:
        unique_ips = df_sessions['ip'].unique()
        df_geo = get_geolocation(unique_ips)
        
        if not df_geo.empty:
            attack_counts = df_sessions['ip'].value_counts().reset_index()
            attack_counts.columns = ['ip', 'count']
            df_map = pd.merge(df_geo, attack_counts, on='ip')
            
            fig_map = px.scatter_geo(
                df_map, lat='lat', lon='lon', color='count', size='count',
                hover_name='city', hover_data=['ip', 'country', 'isp', 'org'],
                projection="natural earth", title="Geolocalización de Intrusos",
                color_continuous_scale="Reds"
            )
            fig_map.update_layout(margin={"r":0,"t":30,"l":0,"b":0}, geo=dict(bgcolor='rgba(0,0,0,0)', showland=True, landcolor="#2E2E2E"))
            st.plotly_chart(fig_map, use_container_width=True)

            col_geo1, col_geo2 = st.columns(2)
            with col_geo1:
                if 'country' in df_map.columns:
                    st.bar_chart(df_map['country'].value_counts(), color="#ff4b4b", horizontal=True)
            with col_geo2:
                if 'org' in df_map.columns:
                    st.bar_chart(df_map['org'].value_counts().head(10), horizontal=True)
        else:
            st.warning("No se pudieron geolocalizar las IPs.")
    else:
        st.info("Sin datos para mostrar en el mapa.")

# PESTAÑA 2: COMANDOS DETALLADOS
with tab2:
    st.subheader("📜 Últimos Comandos")
    if not df_commands.empty:
        terminal_output = ""
        for index, row in df_commands.head(10).iterrows():
            terminal_output += f"[{row['timestamp']}] root@{row['ip']}:~# {row['command']}\n"
        st.code(terminal_output, language="bash")
        st.dataframe(df_commands, use_container_width=True)

# PESTAÑA 3: MALWARE 
with tab3:
    st.subheader("🦠 Análisis VirusTotal")
    if not df_commands.empty:
        malware_cmds = df_commands[df_commands['command'].str.contains("wget|curl", case=False, na=False)].copy()
        if not malware_cmds.empty:
            st.warning(f"⚠️ {len(malware_cmds)} intentos de descarga detectados.")
            cols = ['timestamp', 'ip', 'command']
            if 'vt_result' in malware_cmds.columns: cols.append('vt_result')
            st.dataframe(malware_cmds[cols], use_container_width=True)
        else:
            st.success("✅ Sistema Limpio.")

# PESTAÑA 4: CREDENCIALES 
with tab4:
    st.subheader("🎣 Base de Datos de Accesos")
    if not df_sessions.empty:
        col_a, col_b = st.columns([2, 1])
        with col_a: st.dataframe(df_sessions[['timestamp', 'ip', 'username', 'password']], use_container_width=True)
        with col_b: st.bar_chart(df_sessions['password'].value_counts().head(5), horizontal=True)

# PESTAÑA 5: GRÁFICOS 
with tab5:
    if not df_sessions.empty:
        ip_counts = df_sessions['ip'].value_counts().reset_index()
        ip_counts.columns = ['IP', 'Intentos']
        fig = px.pie(ip_counts, values='Intentos', names='IP', title='Distribución de Ataques', hole=0.4)
        st.plotly_chart(fig, use_container_width=True)

# PESTAÑA 6: MITRE ATT&CK
with tab6:
    st.subheader("🕵️ Análisis MITRE ATT&CK")
    if not df_commands.empty:
        df_mitre = df_commands.copy()
        df_mitre['mitre_tactic'] = df_mitre['command'].apply(map_mitre_tactic)
        st.bar_chart(df_mitre['mitre_tactic'].value_counts(), color="#ff4b4b", horizontal=True)

# Exportar
@st.cache_data
def convert_df(df): return df.to_csv(index=False).encode('utf-8')
st.sidebar.title("🗂️ Exportar Datos")
st.sidebar.markdown("Descarga los logs para tu informe forense.")

if not df_commands.empty:
    st.sidebar.download_button(label="📥 Logs CSV", data=convert_df(df_commands), file_name='shadowshell_logs.csv', mime='text/csv')

# --- NUEVO: BOTÓN GENERAR PDF ---
st.sidebar.markdown("---")
st.sidebar.title("📄 Reporte Ejecutivo")
st.sidebar.markdown("Informe para LinkedIn/Gerencia.")

if st.sidebar.button("🖨️ Generar Informe PDF"):
    with st.spinner("Compilando datos forenses..."):
        # Llamamos a la función con el riesgo calculado en los KPIs
        pdf_bytes = create_pdf(df_sessions, df_commands, avg_risk)
        
        st.sidebar.download_button(
            label="📥 Descargar PDF",
            data=pdf_bytes,
            file_name=f"ShadowShell_Report_{datetime.now().strftime('%Y%m%d')}.pdf",
            mime="application/pdf"
        )
        st.sidebar.success("¡Informe generado!")