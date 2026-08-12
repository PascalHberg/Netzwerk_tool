"""IPP-Probe: Liest Druckerdaten über IPP (Internet Printing Protocol)."""

from __future__ import annotations

from typing import Any

from .models import IPPData


# IPP State Codes (RFC 2911)
IPP_STATES = {
    3: "idle",
    4: "processing",
    5: "stopped",
}


def probe_ipp(
    ip: str,
    port: int = 631,
    use_tls: bool = False,
    timeout: float = 5.0,
) -> IPPData | None:
    """Fragt Druckerdaten über IPP ab.

    Args:
        ip: Ziel-IP
        port: IPP-Port (default: 631)
        use_tls: IPPS verwenden
        timeout: Timeout in Sekunden

    Returns:
        IPPData oder None wenn IPP nicht verfügbar
    """
    try:
        import httpx
        from pyipp import IPP

        protocol = "https" if use_tls else "http"
        ipp_uri = f"{protocol}://{ip}:{port}/ipp/print"
    except ImportError:
        # Fallback ohne pyipp: manuelle IPP-Abfrage via httpx
        return _probe_ipp_raw(ip, port, use_tls, timeout)

    try:
        ipp = IPP(
            host=ip,
            port=port,
            path="/ipp/print",
            protocol="https" if use_tls else "http",
            timeout=timeout,
        )

        # Get-Printer-Attributes Operation (0x000b)
        response = ipp.get_printer_attributes()

        data = IPPData()
        attrs = response.get("printer-attributes", response)

        data.printer_name = str(attrs.get("printer-name", ""))
        data.printer_make_and_model = str(attrs.get("printer-make-and-model", ""))

        state = attrs.get("printer-state", 0)
        data.printer_state = IPP_STATES.get(int(state), str(state))

        reasons = attrs.get("printer-state-reasons", [])
        if isinstance(reasons, list):
            data.printer_state_reasons = [str(r) for r in reasons]
        else:
            data.printer_state_reasons = [str(reasons)]

        uris = attrs.get("printer-uri-supported", [])
        if isinstance(uris, list):
            data.printer_uri_supported = [str(u) for u in uris]
        else:
            data.printer_uri_supported = [str(uris)]

        data.copies_default = _safe_int(attrs.get("copies-default"))
        data.pages_per_minute = _safe_int(attrs.get("pages-per-minute"))

        media = attrs.get("media-supported", [])
        if isinstance(media, list):
            data.media_supported = [str(m) for m in media]
        else:
            data.media_supported = [str(media)]

        color = attrs.get("color-supported")
        data.color_supported = bool(color) if color is not None else None

        duplex = attrs.get("sides-supported")
        data.duplex_supported = bool(duplex) and str(duplex) != "one-sided" if duplex else None

        accepting = attrs.get("printer-is-accepting-jobs")
        data.printer_is_accepting_jobs = bool(accepting) if accepting is not None else None

        data.queued_job_count = _safe_int(attrs.get("queued-job-count"))

        return data

    except Exception:
        # Versuche ohne /ipp/print Pfad
        try:
            ipp = IPP(
                host=ip,
                port=port,
                path="/ipp",
                protocol="https" if use_tls else "http",
                timeout=timeout,
            )
            response = ipp.get_printer_attributes()
            attrs = response.get("printer-attributes", response)

            data = IPPData()
            data.printer_name = str(attrs.get("printer-name", ""))
            data.printer_make_and_model = str(attrs.get("printer-make-and-model", ""))

            state = attrs.get("printer-state", 0)
            data.printer_state = IPP_STATES.get(int(state), str(state))

            reasons = attrs.get("printer-state-reasons", [])
            if isinstance(reasons, list):
                data.printer_state_reasons = [str(r) for r in reasons]
            else:
                data.printer_state_reasons = [str(reasons)]

            return data
        except Exception:
            return None


def _probe_ipp_raw(
    ip: str,
    port: int = 631,
    use_tls: bool = False,
    timeout: float = 5.0,
) -> IPPData | None:
    """Manuelle IPP-Abfrage ohne pyipp, nur mit httpx.

    Sendet einen minimalen Get-Printer-Attributes Request.
    """
    try:
        import httpx

        protocol = "https" if use_tls else "http"
        url = f"{protocol}://{ip}:{port}/ipp/print"

        # IPP Get-Printer-Attributes Request (RFC 8010/8011)
        # Version 2.0, Operation 0x000b (Get-Printer-Attributes)
        pp_request = bytearray()
        # IPP Header
        pp_request += b"\x02\x01"           # version 2.1
        pp_request += b"\x00\x0b"           # operation: Get-Printer-Attributes
        pp_request += b"\x00\x00\x00\x01"  # request-id: 1

        # operation-attributes-tag
        pp_request += b"\x01"
        # attributes-charset
        pp_request += b"\x47\x00\x12"
        pp_request += b"attributes-charset"
        pp_request += b"\x00\x05utf-8"
        # attributes-natural-language
        pp_request += b"\x48\x00\x1b"
        pp_request += b"attributes-natural-language"
        pp_request += b"\x00\x05en-us"
        # printer-uri
        pp_request += b"\x45\x00\x0b"
        pp_request += b"printer-uri"
        uri = f"{protocol}://{ip}:{port}/ipp/print"
        pp_request += bytes([0, len(uri)]) + uri.encode("ascii")
        # requested-attributes
        pp_request += b"\x44\x00\x13"
        pp_request += b"requested-attributes"
        pp_request += b"\x00\x14printer-make-and-model"

        # end-of-attributes
        pp_request += b"\x03"

        headers = {"Content-Type": "application/ipp"}

        client_kwargs: dict[str, Any] = {"timeout": timeout, "verify": False}
        if use_tls:
            client_kwargs["verify"] = False

        with httpx.Client(**client_kwargs) as client:
            resp = client.post(url, content=bytes(pp_request), headers=headers)

        if resp.status_code != 200:
            return None

        body = resp.content
        data = IPPData()

        # Sehr einfache Parsierung: Suche nach lesbaren Strings im Response
        text = body.decode("utf-8", errors="ignore")

        # printer-make-and-model finden
        for marker in [b"printer-make-and-model", b"printer-name", b"printer-state"]:
            idx = body.find(marker)
            if idx > 0:
                # Wert folgt nach OID-Tag + Länge
                val_start = idx + len(marker) + 2  # skip tag + length bytes
                if val_start < len(body):
                    # Nächstes null-terminiertes String-ende finden
                    end = body.find(b"\x00", val_start + 1)
                    if end > val_start:
                        val = body[val_start:end].decode("utf-8", errors="ignore").strip()
                        if marker == b"printer-make-and-model":
                            data.printer_make_and_model = val
                        elif marker == b"printer-name":
                            data.printer_name = val
                        elif marker == b"printer-state":
                            try:
                                state = int(val[0]) if val else 0
                                data.printer_state = IPP_STATES.get(state, val)
                            except (ValueError, IndexError):
                                data.printer_state = val

        if data.printer_make_and_model or data.printer_name:
            return data

        # Wenn nichts gefunden, aber Antwort kam: minimale Daten
        if body:
            data.printer_state = "unknown"
            return data

        return None

    except Exception:
        return None


def _safe_int(value: Any) -> int | None:
    """Sichere Int-Konvertierung."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
