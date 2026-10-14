# Furby OSINT — proyecto académico

Herramienta didáctica en Python para:
- Enumeración pasiva de nombres de dominio mediante Certificate Transparency (`crt.sh`).
- Enumeración activa limitada a registros DNS y comprobación HTTP/HTTPS del dominio base.
- Análisis indicativo de cabeceras de seguridad HTTP.
- Servidor HTTP local para registrar cabeceras `User-Agent`.
- Interfaz Streamlit, historial SQLite y exportación JSON/CSV.

## Uso responsable
Ejecuta pruebas únicamente sobre dominios y sistemas para los que tengas autorización. Las consultas activas generan tráfico. No se realizan explotación, fuerza bruta, escaneo de puertos ni intentos de autenticación. Los resultados OSINT pueden estar obsoletos o ser incompletos. El User-Agent puede falsificarse y no acredita identidad.

## Requisitos
- Python 3.11 o superior recomendado.
- Acceso a Internet para `crt.sh`, DNS y análisis HTTP/HTTPS.
- Docker y Docker Compose (opción recomendada).

## Opción A: Docker Compose
Desde la raíz del proyecto:

```bash
docker compose up --build
```

Abre:
- Interfaz: http://localhost:8501
- Servidor de captura UA (solo accesible desde el equipo local): http://127.0.0.1:8080

Probar el servidor en otra terminal:

```bash
curl -A 'PracticaOSINT/1.0' http://127.0.0.1:8080/prueba
```

Para detener:

```bash
docker compose down
```

Los datos de SQLite y los logs se guardan en el volumen Docker `furby_data`.

## Opción B: ejecutar sin Docker
En Ubuntu:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p data
streamlit run app.py
```

En una segunda terminal, desde la raíz del proyecto:

```bash
source .venv/bin/activate
python -m src.ua_server
```

## Pruebas
```bash
python -m unittest discover -s tests -v
```

## Módulos
- `src/osint_domains.py`: normalización, Certificate Transparency, DNS y comprobación web.
- `src/security_headers.py`: petición web y comprobación de seis cabeceras.
- `src/ua_server.py`: servidor HTTP y registro JSON Lines.
- `src/ua_analyzer.py`: clasificador heurístico de User-Agent.
- `src/storage.py`: historial SQLite.
- `app.py`: interfaz visual.

## Qué puede revelar un User-Agent
Puede sugerir navegador, sistema operativo, librería HTTP, crawler o automatización. Es útil para estadísticas, compatibilidad y análisis de logs. No es una credencial ni un mecanismo fiable de autenticación: puede falsificarse, puede ser genérico y puede contribuir a la huella del navegador. Para identificar crawlers, verifica su procedencia mediante mecanismos apropiados.

## Limitaciones conocidas
- `crt.sh` puede tardar, limitar peticiones o no devolver resultados.
- Los certificados históricos no prueban que un subdominio siga activo.
- El módulo activo verifica el dominio base, no todos los subdominios descubiertos.
- El análisis de cabeceras no sustituye una auditoría de seguridad.
- El servidor HTTP de demostración no incorpora autenticación, TLS ni controles para exposición pública. Mantén el puerto ligado a localhost salvo que hayas diseñado un despliegue protegido.
- Las direcciones IP y los User-Agent son datos potencialmente sensibles en algunos contextos; define retención y acceso apropiados.

## Referencias para la memoria
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN — User-Agent header: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
- Certificate Transparency / crt.sh: https://crt.sh/
- Python `http.server`: https://docs.python.org/3/library/http.server.html
