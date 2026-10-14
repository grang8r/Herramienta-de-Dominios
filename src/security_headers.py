from urllib.parse import urlparse
import requests

CHECKS = {
    "strict-transport-security": ("HSTS", "Refuerza HTTPS en navegadores compatibles; normalmente solo aplica cuando se recibe por HTTPS."),
    "content-security-policy": ("CSP", "Restringe las fuentes de contenido que el navegador puede cargar."),
    "x-content-type-options": ("MIME sniffing", "Se recomienda el valor nosniff."),
    "x-frame-options": ("Protección de marcos", "Puede limitar la incrustación de la página en marcos."),
    "referrer-policy": ("Política de referencia", "Controla qué información de referencia se comparte."),
    "permissions-policy": ("Permisos del navegador", "Permite limitar ciertas funciones disponibles para documentos.")
}

def analyze_headers(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"error": "URL no válida. Usa una URL completa que empiece por http:// o https://."}
    try:
        response = requests.get(
            url, timeout=10, allow_redirects=True, stream=True,
            headers={"User-Agent": "FurbyHeaderAudit/1.0"}
        )
        headers = {k: v for k, v in response.headers.items()}
        normalized = {k.lower(): v for k, v in headers.items()}
        checks = []
        for key, (label, explanation) in CHECKS.items():
            value = normalized.get(key)
            status = "Presente" if value else "Ausente"
            recommendation = "Revisar el valor y el contexto." if value else f"Evaluar si procede configurarla: {explanation}"
            if key == "x-content-type-options" and value and value.lower() != "nosniff":
                recommendation = "La cabecera está presente, pero su valor no es nosniff; revisar configuración."
            checks.append({
                "cabecera": key,
                "control": label,
                "status": status,
                "valor": value or "—",
                "recomendación": recommendation,
            })
        result = {
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": headers,
            "checks": checks,
            "note": "Evaluación indicativa; la ausencia de una cabecera no demuestra por sí sola una vulnerabilidad."
        }
        response.close()
        return result
    except requests.RequestException as exc:
        return {"error": f"No se pudo completar la petición: {type(exc).__name__}: {exc}"}
