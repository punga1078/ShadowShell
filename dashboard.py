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

count = st_autorefresh(interval=2000, limit=None, key="fizzbuzzcounter")
st.title("🕵️‍♂️ ShadowShell - Monitor de Amenazas en Vivo")
st.markdown("---")

# --- FUNCIÓN DE CARGA DE DATOS ---
def load_data():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, 'DATA', 'interacciones.db')
        
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

# --- NUEVO: FUNCIÓN DE GEOLOCALIZACIÓN ---
@st.cache_data(show_spinner=False)
def get_geolocation(ip_list):
    """Convierte lista de IPs en DataFrame con Lat/Lon + ISP simulado para pruebas"""
    locations = []
    
    # Lista de ubicaciones falsas AHORA CON ISP Y ORG
    fake_locations = [
        {
            'lat': 55.7558, 'lon': 37.6173, 'city': 'Moscow', 'country': 'Russia', 
            'isp': 'Rostelecom', 'org': 'Government of Russia'
        },
        {
            'lat': 39.9042, 'lon': 116.4074, 'city': 'Beijing', 'country': 'China', 
            'isp': 'China Unicom', 'org': 'Beijing Infrastructure'
        },
        {
            'lat': 39.0392, 'lon': 125.7625, 'city': 'Pyongyang', 'country': 'North Korea', 
            'isp': 'Star Joint Venture', 'org': 'Kwangmyong Intranet'
        },
        {
            'lat': -23.5505, 'lon': -46.6333, 'city': 'Sao Paulo', 'country': 'Brazil', 
            'isp': 'Vivo', 'org': 'Telefonica Brasil'
        },
        {
            'lat': 38.9072, 'lon': -77.0369, 'city': 'Washington D.C.', 'country': 'USA', 
            'isp': 'Comcast Cable', 'org': 'US DoD Network'
        },
        {
            'lat': 52.5200, 'lon': 13.4050, 'city': 'Berlin', 'country': 'Germany', 
            'isp': 'Deutsche Telekom', 'org': 'Berlin Hosting Service'
        }
    ]

    for ip in ip_list:
        # Detectamos IPs Locales / Docker / Privadas
        is_private = (
            ip == "localhost" or 
            ip.startswith("127.") or 
            ip.startswith("192.168.") or 
            ip.startswith("10.") or 
            (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31) 
        )

        if is_private:
            random.seed(ip) 
            fake = random.choice(fake_locations)
            
            locations.append({
                'ip': ip, 
                'lat': fake['lat'], 
                'lon': fake['lon'], 
                'city': f"{fake['city']} (Simulado)",
                'country': fake['country'],
                'isp': fake['isp'],   # <--- Simulamos el ISP
                'org': fake['org']    # <--- Simulamos la Organización
            })
            continue
            
        # Si es una IP real, consultamos la API
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
            if response['status'] == 'success':
                locations.append({
                    'ip': ip,
                    'lat': response['lat'],
                    'lon': response['lon'],
                    'city': response['city'],
                    'country': response['country'],
                    'isp': response['isp'],
                    'org': response.get('org', 'Unknown')
                })
                time.sleep(1.5)
        except Exception as e:
            print(f"Error geolocalizando {ip}: {e}")
            pass 
            
    if not locations:
        return pd.DataFrame(columns=['lat', 'lon', 'city', 'country', 'isp', 'org'])
    return pd.DataFrame(locations)

# Cargar datos
df_sessions, df_commands = load_data()

# --- SISTEMA DE DETECCIÓN DE AMENAZAS (IDS) ---
st.subheader("🛡️ Monitor de Seguridad")

# 1. Definimos qué buscar
honeyfiles = ["passwords.txt", "wallet_backup.json", "clientes_2025.csv"]
dangerous_cmds = ["wget", "curl", "sudo", "rm -rf"] # <--- Agregamos los comandos aquí

# 2. Combinamos todo en una sola lista de "patrones peligrosos"
all_patterns = honeyfiles + dangerous_cmds

if not df_commands.empty:
    # Creamos una expresión regular que busque CUALQUIERA de esas palabras
    search_pattern = '|'.join(all_patterns)
    
    # Filtramos: ¿El comando contiene alguna de las palabras prohibidas?
    threats = df_commands[df_commands['command'].str.contains(search_pattern, case=False, na=False)]
    
    if not threats.empty:
        # Mensaje más dinámico
        st.error(f"🚨 ALERTA CRÍTICA: ¡{len(threats)} acciones hostiles detectadas (Robo, Malware o Escalada)!")
        
        with st.expander("Ver Detalles del Incidente (Forensics)", expanded=True):
            # Formato condicional para la tabla
            st.dataframe(
                threats[['timestamp', 'ip', 'command']], 
                use_container_width=True
            )
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

st.markdown("---")

# --- PESTAÑAS PRINCIPALES  ---
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🗺️ Mapa de Amenazas", 
    "💀 Actividad en Vivo", 
    "🦠 Malware", 
    "🔐 Credenciales", 
    "📊 Gráficos",
    "🛡️ MITRE ATT&CK"  # <--- NUEVA
])

# PESTAÑA 1: MAPA
with tab1:
    st.subheader("🌍 Origen de los Ataques")
    if not df_sessions.empty:
        unique_ips = df_sessions['ip'].unique()
        df_geo = get_geolocation(unique_ips)
        
        if not df_geo.empty:
            # --- 1. EL MAPA MUNDIAL ---
            attack_counts = df_sessions['ip'].value_counts().reset_index()
            attack_counts.columns = ['ip', 'count']
            
            # Unimos los datos geográficos con el conteo de ataques
            df_map = pd.merge(df_geo, attack_counts, on='ip')
            
            fig_map = px.scatter_geo(
                df_map,
                lat='lat',
                lon='lon',
                color='count',
                size='count',
                hover_name='city',
                # Agregamos ISP y Org al hover para ver detalles al pasar el mouse
                hover_data={'ip': True, 'country': True, 'isp': True, 'org': True, 'lat': False, 'lon': False, 'count': True},
                projection="natural earth",
                title="Geolocalización de Intrusos en Tiempo Real",
                color_continuous_scale="Reds"
            )
            fig_map.update_layout(
                margin={"r":0,"t":30,"l":0,"b":0},
                geo=dict(bgcolor='rgba(0,0,0,0)', showland=True, landcolor="#2E2E2E", showocean=True, oceancolor="#0E1117")
            )
            st.plotly_chart(fig_map, use_container_width=True)

            # --- 2. ESTADÍSTICAS DE ISP Y ORGANIZACIÓN (NUEVO) ---
            st.markdown("---")
            col_isp1, col_isp2 = st.columns(2)

            with col_isp1:
                st.subheader("🏢 Top Organizaciones")
                # Verificamos que la columna 'org' exista (por si la API falló)
                if 'org' in df_map.columns:
                    org_counts = df_map['org'].value_counts().head(5)
                    st.bar_chart(org_counts, color="#ff4b4b", horizontal=True)
                else:
                    st.info("Datos de organización no disponibles aún.")

            with col_isp2:
                st.subheader("📡 Distribución por ISP")
                if 'isp' in df_map.columns:
                    isp_counts = df_map['isp'].value_counts().reset_index()
                    isp_counts.columns = ['ISP', 'Count']
                    
                    fig_pie = px.pie(
                        isp_counts, 
                        values='Count', 
                        names='ISP', 
                        hole=0.4,
                        color_discrete_sequence=px.colors.sequential.RdBu
                    )
                    fig_pie.update_layout(margin=dict(t=0, b=0, l=0, r=0))
                    st.plotly_chart(fig_pie, use_container_width=True)
                else:
                    st.info("Datos de ISP no disponibles aún.")

        else:
            st.warning("No se pudieron geolocalizar las IPs (o no hay conexión a internet).")
    else:
        st.info("Sin datos para mostrar en el mapa.")

# PESTAÑA 2: COMANDOS
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
        # Filtramos comandos que sean wget o curl
        malware_cmds = df_commands[df_commands['command'].str.contains("wget|curl", case=False, na=False)].copy()
        
        if not malware_cmds.empty:
            st.warning(f"⚠️ Se han detectado {len(malware_cmds)} intentos de descarga de payload.")
            
            # --- TABLA MEJORADA ---
            # Seleccionamos columnas, incluyendo la nueva 'vt_result' si existe
            cols_to_show = ['timestamp', 'ip', 'command']
            if 'vt_result' in malware_cmds.columns:
                cols_to_show.append('vt_result')
            
            # Mostramos la tabla principal
            st.dataframe(
                malware_cmds[cols_to_show], 
                use_container_width=True
            )
            
            # --- DETALLE VISUAL ---
            st.markdown("### 🔍 Detalles del Análisis")
            for index, row in malware_cmds.iterrows():
                # Solo mostramos si hay un resultado de VT
                if 'vt_result' in row and row['vt_result']:
                    with st.expander(f"Reporte para: {row['command']}"):
                        st.info(f"📅 Fecha: {row['timestamp']} | 🌍 IP: {row['ip']}")
                        
                        # Colorear según el resultado
                        result_text = row['vt_result']
                        if "PELIGRO" in result_text or "malicious" in str(result_text).lower():
                            st.error(result_text)
                        elif "Limpio" in result_text:
                            st.success(result_text)
                        else:
                            st.write(result_text)

            # Gráfico de Dominios 
            st.markdown("---")
            st.subheader("🌐 Dominios más atacados")
            try:
                urls = malware_cmds['command'].str.extract(r'https?://([^/:\s]+)')[0].value_counts()
                if not urls.empty:
                    st.bar_chart(urls, horizontal=True, color="#ff4b4b") 
            except Exception as e:
                st.error(f"Error analizando URLs: {e}")
            
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
    st.markdown("Clasificación automática de las intenciones del atacante basada en sus comandos.")
    
    if not df_commands.empty:
        # Creamos una copia para no afectar los otros gráficos
        df_mitre = df_commands.copy()
        
        # Aplicamos la función a cada comando
        df_mitre['mitre_tactic'] = df_mitre['command'].apply(map_mitre_tactic)
        
        # Contamos las tácticas
        mitre_counts = df_mitre['mitre_tactic'].value_counts()
        
        # --- DISEÑO VISUAL ---
        col_m1, col_m2 = st.columns([2, 1])
        
        with col_m1:
            st.markdown("#### 🔥 Tácticas más utilizadas")
            # Gráfico de barras horizontal
            st.bar_chart(mitre_counts, color="#ff4b4b", horizontal=True)
            
        with col_m2:
            st.markdown("#### 🧠 Resumen de Inteligencia")
            # Métricas clave
            if not mitre_counts.empty:
                top_tactic = mitre_counts.idxmax()
                top_count = mitre_counts.max()
                st.metric(label="Táctica Principal", value=top_tactic)
                st.metric(label="Eventos Detectados", value=top_count)
            else:
                st.write("Sin datos suficientes.")

        st.divider()
        
        # --- TABLA DETALLADA CON FILTRO ---
        st.markdown("### 🔬 Desglose Forense")
        
        # Filtro interactivo
        opciones = ["Todos"] + list(mitre_counts.index.unique())
        tactic_filter = st.selectbox("Filtrar por Táctica Específica:", opciones)
        
        if tactic_filter != "Todos":
            df_show = df_mitre[df_mitre['mitre_tactic'] == tactic_filter]
        else:
            df_show = df_mitre
            
        # Mostramos la tabla limpia
        st.dataframe(
            df_show[['timestamp', 'ip', 'command', 'mitre_tactic']], 
            use_container_width=True,
            hide_index=True
        )
        
    else:
        st.info("Esperando datos de comandos para generar la matriz de ataque...")

# Función para convertir DF a CSV
@st.cache_data
def convert_df(df):
    return df.to_csv(index=False).encode('utf-8')

st.sidebar.title("🗂️ Exportar Datos")
st.sidebar.markdown("Descarga los logs para tu informe forense.")

if not df_commands.empty:
    csv = convert_df(df_commands)
    st.sidebar.download_button(
        label="📥 Descargar Logs de Comandos (CSV)",
        data=csv,
        file_name='shadowshell_logs.csv',
        mime='text/csv',
    )