def classify_user_agent(ua: str) -> str:
    """Clasificación heurística; el User-Agent puede falsificarse."""
    s = (ua or "").lower()
    if "googlebot" in s:
        return "Se declara como Googlebot (verificar identidad)"
    if "bingbot" in s:
        return "Se declara como Bingbot (verificar identidad)"
    if "curl/" in s:
        return "curl / cliente de línea de comandos"
    if "python-requests" in s:
        return "Python Requests"
    if "python-urllib" in s:
        return "Python urllib"
    if "firefox/" in s:
        return "Firefox"
    if "edg/" in s:
        return "Microsoft Edge"
    if "chrome/" in s and "safari/" in s:
        return "Navegador Chromium (posible Chrome/derivado)"
    if "safari/" in s:
        return "Safari o navegador compatible"
    if "mozilla/" in s:
        return "Navegador u otro cliente con cadena Mozilla"
    if not s:
        return "Vacío"
    return "Desconocido / cliente personalizado"
