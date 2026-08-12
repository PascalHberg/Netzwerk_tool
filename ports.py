"""Port-Scanner: Prüft typische Drucker- und Dienst-Ports."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import PortInfo

# Typische Drucker-Ports
PRINTER_PORTS: list[PortInfo] = [
    PortInfo(port=80, protocol="tcp", service="http"),
    PortInfo(port=443, protocol="tcp", service="https"),
    PortInfo(port=515, protocol="tcp", service="lpd"),
    PortInfo(port=631, protocol="tcp", service="ipp"),
    PortInfo(port=9100, protocol="tcp", service="jetdirect"),
    PortInfo(port=161, protocol="udp", service="snmp"),
    PortInfo(port=23, protocol="tcp", service="telnet"),
    PortInfo(port=21, protocol="tcp", service="ftp"),
    PortInfo(port=22, protocol="tcp", service="ssh"),
    PortInfo(port=139, protocol="tcp", service="netbios-ssn"),
    PortInfo(port=445, protocol="tcp", service="microsoft-ds"),
]

# Ports, die stark auf "Drucker" hindeuten
STRONG_PRINTER_PORTS = {631, 9100, 515}


def _check_tcp_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Prüft ob ein TCP-Port offen ist."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _check_udp_snmp(ip: str, port: int = 161, timeout: float = 1.0) -> bool:
    """Prüft ob SNMP (UDP 161) antwortet mit einer simplen GetRequest."""
    try:
        # Minimaler SNMPv2c GetRequest für sysDescr.0
        # SNMP Community "public"
        snmp_packet = bytes.fromhex(
            "302902010104067075626c6963a01c0204"
            "7c4f1e3502010002010030103e0e040006"
            "082b060102010101000500"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(snmp_packet, (ip, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return len(data) > 0
    except Exception:
        return False


def scan_ports(
    ip: str,
    timeout: float = 1.0,
    ports: list[PortInfo] | None = None,
) -> list[PortInfo]:
    """Scannt alle definierten Ports eines Hosts.

    Args:
        ip: Ziel-IP
        timeout: Timeout pro Port
        ports: Liste der zu prüfenden Ports (default: PRINTER_PORTS)

    Returns:
        Liste von PortInfo mit aktualisiertem open-Status
    """
    if ports is None:
        ports = [PortInfo(p.port, p.protocol, p.service) for p in PRINTER_PORTS]

    def _check(port_info: PortInfo) -> PortInfo:
        if port_info.protocol == "udp" and port_info.port == 161:
            port_info.open = _check_udp_snmp(ip, port_info.port, timeout)
        else:
            port_info.open = _check_tcp_port(ip, port_info.port, timeout)
        return port_info

    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        futures = [executor.submit(_check, p) for p in ports]
        results = []
        for future in as_completed(futures):
            results.append(future.result())

    # Sortiert nach Port-Nummer
    results.sort(key=lambda p: p.port)
    return results


def has_printer_ports(ports: list[PortInfo]) -> bool:
    """Prüft ob die offenen Ports auf einen Drucker hindeeten."""
    open_ports = {p.port for p in ports if p.open}
    return bool(open_ports & STRONG_PRINTER_PORTS)


def get_open_ports(ports: list[PortInfo]) -> list[int]:
    """Gibt alle offenen Port-Nummern zurück."""
    return [p.port for p in ports if p.open]
