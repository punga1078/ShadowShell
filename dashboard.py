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
# 🚀 INICIO DEL DASHBOARD REAL
# ==========================================

# Configuración de la página (Solo se ejecuta si pasó el login)
st.set_page_config(
    page_title="ShadowShell | C2",
    page_icon="🕵️‍♂️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

count = st_autorefresh(interval=5000, limit=None, key="fizzbuzzcounter") # Subí a 5s para no saturar
st.title("🕵️‍♂️ ShadowShell - Monitor de Amenazas en Vivo")
st.markdown("---")

# --- FUNCIÓN DE CARGA DE DATOS ---
def load_data():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        # Usamos 'data' en minúscula como corregimos antes
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
    
# --- FUNCIÓN MITRE ATT&CK ---
def map_mitre_tactic(command):
    """Clasifica el comando según la matriz MITRE ATT&CK"""
    cmd = command.lower()
    
    # Diccionario de reglas simples
    if "wget" in cmd or "curl" in cmd:
        return "Resource Development (T1588)" # Descargar herramientas
    elif "rm " in cmd or "history -c" in cmd:
        return "Defense Evasion (T1070)"      # Borrar huellas
    elif "cat /etc/shadow" in cmd or "cat passwords" in cmd:
        return "Credential Access (T1003)"    # Robar claves
    elif "sudo" in cmd or "su " in cmd:
        return "Privilege Escalation (T1068)" # Intentar ser root
    elif "ls" in cmd or "ps" in cmd or "whoami" in cmd:
        return "Discovery (T1082)"            # Espiar el sistema
    elif "./" in cmd or "python" in cmd or "bash" in cmd:
        return "Execution (T1059)"            # Ejecutar scripts
    else:
        return "Uncategorized"

# --- NUEVO: FUNCIÓN DE GEOLOCALIZACIÓN OPTIMIZADA ---
# 1. Función PEQUEÑA que se encarga de UNA sola IP (Esta es la que tiene memoria)
@st.cache_data(show_spinner=False)
def get_single_ip_data(ip):
    """Consulta la API para una sola IP y guarda el resultado en memoria"""
    
    # Simulación para IPs privadas (igual que antes)
    if ip == "localhost" or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        fake_locations = [
            {'lat': 55.7558, 'lon': 37.6173, 'city': 'Moscow', 'country': 'Russia'},
            {'lat': 39.9042, 'lon': 116.4074, 'city': 'Beijing', 'country': 'China'},
            {'lat': -23.5505, 'lon': -46.6333, 'city': 'Sao Paulo', 'country': 'Brazil'}
        ]
        random.seed(ip)
        fake = random.choice(fake_locations)
        return {
            'ip': ip, 'lat': fake['lat'], 'lon': fake['lon'], 
            'city': f"{fake['city']} (Simulado)", 'country': fake['country'], 
            'isp': 'Private', 'org': 'Private'
        }

    # Consulta REAL a la API
    try:
        # Pausa pequeña para respetar límites (solo se ejecuta si la IP es nueva)
        time.sleep(1.1) 
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        
        if response['status'] == 'success':
            return {
                'ip': ip,
                'lat': response['lat'],
                'lon': response['lon'],
                'city': response['city'],
                'country': response['country'],
                'isp': response['isp'],
                'org': response.get('org', 'Unknown')
            }
        else:
            return None # Falló la API para esta IP específica
    except:
        return None # Error de conexión

# 2. Función PRINCIPAL (Ya no lleva caché aquí, porque la tiene la función de arriba)
def get_geolocation(ip_list):
    locations = []
    
    # Barra de progreso visual si hay muchas IPs nuevas
    if len(ip_list) > 0:
        progress_text = "Geolocalizando atacantes..."
        my_bar = st.progress(0, text=progress_text)

    for i, ip in enumerate(ip_list):
        data = get_single_ip_data(ip) # <--- Aquí ocurre la magia del caché
        if data:
            locations.append(data)
        
        # Actualizar barra de progreso
        if len(ip_list) > 0:
            my_bar.progress((i + 1) / len(ip_list), text=progress_text)
            
    if len(ip_list) > 0:
        my_bar.empty() # Borrar la barra cuando termine

    if not locations:
        return pd.DataFrame(columns=['lat', 'lon', 'city', 'country', 'isp', 'org'])
        
    return pd.DataFrame(locations)

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
with col3: st.metric("Comandos Capturados", len(df_commands))
with col4: st.metric("Usuario + Común", df_sessions['username'].mode()[0] if not df_sessions.empty else "N/A")

# =========================================================
#  NUEVO: TABLAS SEPARADAS (SOLICITUD 1)
# =========================================================
st.markdown("---")
col_logins, col_cmds = st.columns(2)

with col_logins:
    st.subheader("🕵️ Últimos Logins")
    st.caption("Quién logró entrar (User/Pass)")
    if not df_sessions.empty:
        st.dataframe(df_sessions[['timestamp', 'ip', 'username', 'password']], hide_index=True, use_container_width=True)
    else:
        st.info("Sin registros de sesión.")

with col_cmds:
    st.subheader("⌨️ Comandos Ejecutados")
    st.caption("Qué escribieron (Shell + Exec)")
    if not df_commands.empty:
        # Mostramos vt_result si existe (para ver los EXEC capturados)
        cols_cmd = ['timestamp', 'ip', 'command']
        if 'vt_result' in df_commands.columns:
            cols_cmd.append('vt_result')
        st.dataframe(df_commands[cols_cmd], hide_index=True, use_container_width=True)
    else:
        st.info("Sin comandos capturados.")

st.markdown("---")

# --- PESTAÑAS PRINCIPALES  ---
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🗺️ Mapa de Amenazas", 
    "💀 Actividad en Vivo", 
    "🦠 Malware", 
    "🔐 Credenciales", 
    "📊 Gráficos",
    "🛡️ MITRE ATT&CK" 
])

# PESTAÑA 1: MAPA (ACTUALIZADA CON GRÁFICO DE PAÍSES)
with tab1:
    st.subheader("🌍 Origen de los Ataques")
    if not df_sessions.empty:
        unique_ips = df_sessions['ip'].unique()
        df_geo = get_geolocation(unique_ips)
        
        if not df_geo.empty:
            # --- 1. EL MAPA MUNDIAL ---
            attack_counts = df_sessions['ip'].value_counts().reset_index()
            attack_counts.columns = ['ip', 'count']
            
            df_map = pd.merge(df_geo, attack_counts, on='ip')
            
            fig_map = px.scatter_geo(
                df_map,
                lat='lat',
                lon='lon',
                color='count',
                size='count',
                hover_name='city',
                hover_data={'ip': True, 'country': True, 'isp': True, 'org': True, 'lat': False, 'lon': False, 'count': True},
                projection="natural earth",
                title="Geolocalización de Intrusos",
                color_continuous_scale="Reds"
            )
            fig_map.update_layout(
                margin={"r":0,"t":30,"l":0,"b":0},
                geo=dict(bgcolor='rgba(0,0,0,0)', showland=True, landcolor="#2E2E2E", showocean=True, oceancolor="#0E1117")
            )
            st.plotly_chart(fig_map, use_container_width=True)

            # --- 2. ESTADÍSTICAS (ORGANIZACIÓN + PAÍSES) ---
            st.markdown("---")
            col_geo1, col_geo2 = st.columns(2)

            with col_geo1:
                st.subheader("🏳️ Top Países (NUEVO)") # <--- SOLICITUD 2
                if 'country' in df_map.columns:
                    country_counts = df_map['country'].value_counts()
                    st.bar_chart(country_counts, color="#ff4b4b", horizontal=True)
                else:
                    st.info("Datos de país no disponibles.")

            with col_geo2:
                st.subheader("🏢 Top Organizaciones")
                if 'org' in df_map.columns:
                    org_counts = df_map['org'].value_counts().head(10)
                    st.bar_chart(org_counts, horizontal=True)
                else:
                    st.info("Datos de organización no disponibles.")

            # --- 3. GRÁFICO DE TORTA ISP ---
            st.markdown("---")
            st.subheader("📡 Distribución por ISP")
            if 'isp' in df_map.columns:
                isp_counts = df_map['isp'].value_counts().reset_index()
                isp_counts.columns = ['ISP', 'Count']
                fig_pie = px.pie(isp_counts, values='Count', names='ISP', hole=0.4, color_discrete_sequence=px.colors.sequential.RdBu)
                st.plotly_chart(fig_pie, use_container_width=True)

        else:
            st.warning("No se pudieron geolocalizar las IPs (o no hay conexión a internet).")
    else:
        st.info("Sin datos para mostrar en el mapa.")

# PESTAÑA 2: COMANDOS DETALLADOS
with tab2:
    st.subheader("📜 Últimos Comandos Ejecutados")
    if not df_commands.empty:
        terminal_output = ""
        for index, row in df_commands.head(10).iterrows():
            terminal_output += f"[{row['timestamp']}] root@{row['ip']}:~# {row['command']}\n"
        st.code(terminal_output, language="bash")
        st.dataframe(df_commands, use_container_width=True)
    else:
        st.info("Esperando comandos...")

# PESTAÑA 3: MALWARE 
with tab3:
    st.subheader("🦠 Análisis de Amenazas (VirusTotal)")
    if not df_commands.empty:
        malware_cmds = df_commands[df_commands['command'].str.contains("wget|curl", case=False, na=False)].copy()
        if not malware_cmds.empty:
            st.warning(f"⚠️ Se han detectado {len(malware_cmds)} intentos de descarga de payload.")
            cols_to_show = ['timestamp', 'ip', 'command']
            if 'vt_result' in malware_cmds.columns:
                cols_to_show.append('vt_result')
            st.dataframe(malware_cmds[cols_to_show], use_container_width=True)
        else:
            st.success("✅ Limpio: No se han detectado intentos de descarga de malware todavía.")
    else:
        st.info("Esperando datos para analizar...")

# PESTAÑA 4: CREDENCIALES 
with tab4:
    st.subheader("🎣 Base de Datos de Accesos")
    if not df_sessions.empty:
        col_a, col_b = st.columns([2, 1])
        with col_a:
            st.dataframe(df_sessions[['timestamp', 'ip', 'username', 'password']], use_container_width=True)
        with col_b:
            st.write("Top 5 Contraseñas")
            top_pass = df_sessions['password'].value_counts().head(5)
            st.bar_chart(top_pass, horizontal=True)
    else:
        st.info("Nadie ha intentado loguearse aún.")

# PESTAÑA 5: GRÁFICOS 
with tab5:
    if not df_sessions.empty:
        ip_counts = df_sessions['ip'].value_counts().reset_index()
        ip_counts.columns = ['IP', 'Intentos']
        fig = px.pie(ip_counts, values='Intentos', names='IP', title='Distribución de Ataques', hole=0.4)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Esperando datos para graficar...")

# PESTAÑA 6: MITRE ATT&CK
with tab6:
    st.subheader("🕵️ Análisis Táctico (MITRE Framework)")
    if not df_commands.empty:
        df_mitre = df_commands.copy()
        df_mitre['mitre_tactic'] = df_mitre['command'].apply(map_mitre_tactic)
        mitre_counts = df_mitre['mitre_tactic'].value_counts()
        
        col_m1, col_m2 = st.columns([2, 1])
        with col_m1:
            st.bar_chart(mitre_counts, color="#ff4b4b", horizontal=True)
        with col_m2:
            if not mitre_counts.empty:
                st.metric(label="Táctica Principal", value=mitre_counts.idxmax())
                st.metric(label="Eventos", value=mitre_counts.max())
    else:
        st.info("Esperando datos de comandos...")

# Exportar Datos
@st.cache_data
def convert_df(df):
    return df.to_csv(index=False).encode('utf-8')

st.sidebar.title("🗂️ Exportar")
if not df_commands.empty:
    csv = convert_df(df_commands)
    st.sidebar.download_button(label="📥 Logs Comandos (CSV)", data=csv, file_name='shadowshell_logs.csv', mime='text/csv')