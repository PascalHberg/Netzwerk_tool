"""HTTP-Probe: Liest Metadaten vom Web-Interface des Druckers."""

from __future__ import annotations

import re

from .models import HTTPData


def probe_http(
    ip: str,
    port: int = 80,
    use_https: bool = False,
    timeout: float = 5.0,
) -> HTTPData | None:
    """Fragt Metadaten vom Web-Interface ab.

    Liest nur den Titel und Server-Header, keine Logins.

    Args:
        ip: Ziel-IP
        port: HTTP-Port
        use_https: HTTPS verwenden
        timeout: Timeout in Sekunden

    Returns:
        HTTPData oder None
    """
    try:
        import httpx
    except ImportError:
        print("  [!] httpx nicht installiert - überspringe HTTP-Probe")
        return None

    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}:{port}/"

    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            resp = client.get(url)

        data = HTTPData()
        data.status_code = resp.status_code

        # Server-Header
        data.server_header = resp.headers.get("server", "")

        # Title aus HTML
        text = resp.text
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if title_match:
            data.title = title_match.group(1).strip()

        # Redirect verfolgen
        if resp.url != url:
            data.redirect_url = str(resp.url)

        return data

    except Exception:
        return None
