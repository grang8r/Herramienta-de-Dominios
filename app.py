import json
import os
import pandas as pd
import streamlit as st
from src.osint_domains import passive_enum, active_enum
from src.security_headers import analyze_headers
from src.storage import init_db, save_scan, list_scans
from src.reporting import dataframe_csv

st.set_page_config(page_title="Furby OSINT", page_icon="🔎", layout="wide")
init_db()

st.title("🔎 Furby OSINT")
st.caption("Reconocimiento de dominios, análisis de cabeceras HTTP y observación de User-Agent.")
st.warning("Utiliza únicamente dominios y sistemas para los que tengas autorización. La enumeración activa realiza consultas DNS y peticiones HTTP/HTTPS.")

tab_osint, tab_headers, tab_ua, tab_history = st.tabs([
    "🌐 OSINT de dominios", "🛡️ Cabeceras HTTP", "🧾 User-Agent", "🗂️ Historial"
])

with tab_osint:
    st.subheader("Enumeración de dominio")
    domain = st.text_input("Dominio (sin https:// ni rutas)", placeholder="example.com", key="domain")
    c1, c2 = st.columns(2)
    with c1:
        do_passive = st.checkbox("Pasiva: Certificate Transparency (crt.sh)", value=True)
    with c2:
        do_active = st.checkbox("Activa: DNS + comprobación HTTP/HTTPS", value=True)
    max_hosts = st.slider("Máximo de hosts a verificar", 1, 50, 15)
    if st.button("Iniciar enumeración", type="primary", key="enum"):
        if not domain.strip():
            st.error("Introduce un dominio.")
        elif not (do_passive or do_active):
            st.error("Selecciona al menos un tipo de enumeración.")
        else:
            results = []
            with st.spinner("Recopilando información…"):
                if do_passive:
                    try:
                        results.extend(passive_enum(domain.strip()))
                    except Exception as e:
                        st.error(f"Falló la enumeración pasiva: {e}")
                if do_active:
                    try:
                        results.extend(active_enum(domain.strip(), max_hosts=max_hosts))
                    except Exception as e:
                        st.error(f"Falló la enumeración activa: {e}")
            if results:
                df = pd.DataFrame(results).drop_duplicates(subset=["hostname", "source"], keep="last")
                save_scan("domain", domain.strip(), df.to_dict(orient="records"))
                st.success(f"Se han recopilado {len(df)} registros.")
                st.dataframe(df, use_container_width=True, hide_index=True)
                st.download_button("Descargar CSV", dataframe_csv(df), "furby_domain_results.csv", "text/csv")
                st.download_button("Descargar JSON", json.dumps(df.to_dict(orient="records"), indent=2, ensure_ascii=False), "furby_domain_results.json", "application/json")
            else:
                st.info("No se han encontrado resultados. Comprueba el dominio y la conexión.")

with tab_headers:
    st.subheader("Analizador de cabeceras de seguridad")
    url = st.text_input("URL completa", placeholder="https://example.com")
    if st.button("Analizar cabeceras", type="primary"):
        if not url.strip():
            st.error("Introduce una URL.")
        else:
            with st.spinner("Realizando petición HTTP/HTTPS…"):
                result = analyze_headers(url.strip())
            if result.get("error"):
                st.error(result["error"])
            else:
                a, b, c = st.columns(3)
                a.metric("Código HTTP", result["status_code"])
                b.metric("Cabeceras evaluadas", len(result["checks"]))
                c.metric("Controles presentes", sum(1 for x in result["checks"] if x["status"] == "Presente"))
                st.write(f"**URL final:** {result['final_url']}")
                st.dataframe(pd.DataFrame(result["checks"]), use_container_width=True, hide_index=True)
                with st.expander("Ver todas las cabeceras recibidas"):
                    st.json(result["headers"])
                save_scan("headers", url.strip(), result)
                st.download_button("Descargar informe JSON", json.dumps(result, indent=2, ensure_ascii=False), "furby_headers_report.json", "application/json")

with tab_ua:
    st.subheader("Captura de User-Agent")
    st.write("El servidor local registra las peticiones recibidas en `data/user_agents.jsonl`.")
    log_path = "data/user_agents.jsonl"
    if os.path.exists(log_path):
        events = []
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if events:
            df = pd.DataFrame(events)
            st.metric("Peticiones registradas", len(df))
            st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
            st.download_button("Descargar registros CSV", dataframe_csv(df), "furby_user_agents.csv", "text/csv")
        else:
            st.info("El fichero existe, pero todavía no contiene registros válidos.")
    else:
        st.info("Aún no hay registros. Inicia el servidor UA y realiza una petición.")
    st.code("curl -A 'PracticaOSINT/1.0' http://127.0.0.1:8080/prueba", language="bash")
    st.caption("El User-Agent es texto proporcionado por el cliente y puede falsificarse. No debe usarse como prueba de identidad.")

with tab_history:
    st.subheader("Historial de análisis")
    history = list_scans()
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
    else:
        st.info("Todavía no se han guardado análisis.")
