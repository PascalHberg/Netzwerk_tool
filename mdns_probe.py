"""mDNS/Bonjour-Erkennung: Findet Drucker über Zeroconf-Dienste."""

from __future__ import annotations

import socket
import time
from typing import Any

from .models import MDNSData

# mDNS-Diensttypen, die auf Drucker hindeuten
PRINTER_SERVICE_TYPES = [
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_scanner._tcp.local.",
    "_ipp-lpr._tcp.local.",
]


def discover_mdns_devices(
    timeout: float = 5.0,
    service_types: list[str] | None = None,
) -> dict[str, MDNSData]:
    """Sucht über mDNS/Bonjour nach Druckern im Netzwerk.

    Args:
        timeout: Suchdauer in Sekunden
        service_types: Liste der Service-Typen (default: PRINTER_SERVICE_TYPES)

    Returns:
        Dict IP -> MDNSData
    """
    if service_types is None:
        service_types = PRINTER_SERVICE_TYPES

    results: dict[str, MDNSData] = {}

    try:
        from zeroconf import Zeroconf, ServiceBrowser
    except ImportError:
        print("  [!] zeroconf nicht installiert - überspringe mDNS-Scan")
        return results

    class _MDNSListener:
        def __init__(self) -> None:
            self.devices: dict[str, MDNSData] = {}

        def add_service(self, zeroconf: Any, service_type: str, name: str) -> None:
            info = zeroconf.get_service_info(service_type, name)
            if info and info.addresses:
                for addr in info.addresses:
                    ip = socket.inet_ntoa(addr)
                    if ip in self.devices:
                        continue
                    properties = {}
                    if info.properties:
                        for k, v in info.properties.items():
                            key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
                            val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                            properties[key] = val

                    mdns = MDNSData(
                        service_type=service_type,
                        service_name=name,
                        hostname=info.server or "",
                        port=info.port,
                        properties=properties,
                    )
                    self.devices[ip] = mdns

        def remove_service(self, zeroconf: Any, service_type: str, name: str) -> None:
            pass

        def update_service(self, zeroconf: Any, service_type: str, name: str) -> None:
            self.add_service(zeroconf, service_type, name)

    listener = _MDNSListener()
    zeroconf = Zeroconf()
    browsers: list[Any] = []

    try:
        for st in service_types:
            browsers.append(ServiceBrowser(zeroconf, st, listener))

        time.sleep(timeout)
    except Exception as e:
        print(f"  [!] mDNS-Fehler: {e}")
    finally:
        for b in browsers:
            try:
                b.cancel()
            except Exception:
                pass
        zeroconf.close()

    return listener.devices
