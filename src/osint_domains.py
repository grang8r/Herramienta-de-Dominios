import re
import socket
from urllib.parse import urlparse

import requests
import dns.resolver

TIMEOUT = 8
USER_AGENT = "FurbyOSINT-StudentProject/1.0"

def normalize_domain(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0].strip(".").lower()
    if not value or "." not in value or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValueError("Dominio no válido. Introduce un nombre como example.com.")
    if ".." in value or value.startswith("-") or value.endswith("-"):
        raise ValueError("Formato de dominio no válido.")
    return value

def passive_enum(domain: str) -> list[dict]:
    """Consulta pública de Certificate Transparency en crt.sh."""
    domain = normalize_domain(domain)
    response = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        headers={"User-Agent": USER_AGENT},
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    try:
        records = response.json()
    except ValueError:
        raise RuntimeError("crt.sh no devolvió JSON válido.")
    hosts = set()
    for record in records:
        for name in str(record.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                hosts.add(name)
    return [
        {"hostname": host, "ip": "", "http_status": "", "source": "Certificate Transparency (crt.sh)",
         "method": "Pasiva", "details": "Nombre observado en certificados públicos; no implica que siga activo."}
        for host in sorted(hosts)
    ]

def active_enum(domain: str, max_hosts: int = 15) -> list[dict]:
    """Consulta registros DNS del dominio y verifica por HTTP/HTTPS solo el dominio base."""
    domain = normalize_domain(domain)
    records = []
    ips = set()
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=TIMEOUT)
            values = []
            for answer in answers:
                value = str(answer).strip()
                values.append(value)
                if record_type in ("A", "AAAA"):
                    ips.add(value)
            records.append({
                "hostname": domain, "ip": ", ".join(sorted(ips)), "http_status": "",
                "source": f"DNS {record_type}", "method": "Activa",
                "details": "; ".join(values)[:1000]
            })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            continue
        except Exception as exc:
            records.append({
                "hostname": domain, "ip": "", "http_status": "", "source": f"DNS {record_type}",
                "method": "Activa", "details": f"Error: {type(exc).__name__}"
            })

    # Verificación web acotada al dominio indicado: no hace barrido de puertos.
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{domain}",
                headers={"User-Agent": USER_AGENT},
                timeout=TIMEOUT,
                allow_redirects=True,
                stream=True,
            )
            records.append({
                "hostname": domain, "ip": ", ".join(sorted(ips)), "http_status": r.status_code,
                "source": f"{scheme.upper()} request", "method": "Activa",
                "details": f"URL final: {r.url}; Content-Type: {r.headers.get('Content-Type', '')}"
            })
            r.close()
            break
        except requests.RequestException as exc:
            records.append({
                "hostname": domain, "ip": ", ".join(sorted(ips)), "http_status": "",
                "source": f"{scheme.upper()} request", "method": "Activa",
                "details": f"No disponible: {type(exc).__name__}"
            })
    return records[:max_hosts + 10]
