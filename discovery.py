"""Netzwerk-Erkennung: lokales Subnetz finden und Hosts scannen."""

from __future__ import annotations

import ipaddress
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator

try:
    import netifaces
except ImportError:
    netifaces = None  # type: ignore


def get_local_subnet() -> str:
    """Erkennt das lokale Subnetz automatisch.

    Nutzt netifaces, um die IP und Subnetzmaske der Standard-Route zu finden.
    Fallback: 192.168.178.0/24 (typisch für deutsche Heimrouter).
    """
    if netifaces:
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get("default", {})
            if default_gateway:
                iface = default_gateway[1]
                addrs = netifaces.ifaddresses(iface)
                inet = addrs.get(netifaces.AF_INET, [])
                if inet:
                    ip = inet[0]["addr"]
                    netmask = inet[0].get("netmask", "255.255.255.0")
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
        except Exception:
            pass

    # Fallback
    return "192.168.178.0/24"


def get_local_ip() -> str:
    """Gibt die lokale IP-Adresse zurück."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Pingt einen Host an. True wenn erreichbar."""
    # Versuche ICMP-Ping
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout)), ip],
            capture_output=True,
            timeout=timeout + 1,
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass

    # Fallback: TCP-Probe auf häufige Ports
    for port in [80, 443, 445, 631, 9100]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            continue

    return False


def _resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """Versucht den Hostnamen per Reverse-DNS aufzulösen."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        sock.close()
        return hostname
    except Exception:
        return ""


def _get_arp_mac(ip: str) -> str:
    """Versucht die MAC-Adresse über den ARP-Cache zu finden."""
    try:
        # ARP-Cache auslesen
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=2,
        )
        output = result.stdout.strip()
        # Format: "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        if "lladdr" in output:
            parts = output.split()
            for i, part in enumerate(parts):
                if part == "lladdr" and i + 1 < len(parts):
                    return parts[i + 1].lower()
    except Exception:
        pass

    # Fallback: arp-Befehl
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True,
            text=True,
            timeout=2,
        )
        for line in result.stdout.splitlines():
            if ip in line:
                # MAC-Adresse finden (Format xx:xx:xx:xx:xx:xx)
                for part in line.split():
                    if ":" in part and len(part) == 17:
                        return part.lower()
    except Exception:
        pass

    return ""


def scan_network(
    subnet: str,
    timeout: float = 1.0,
    max_workers: int = 50,
) -> Iterator[tuple[str, bool, str, str]]:
    """Scannt ein Subnetz nach aktiven Hosts.

    Args:
        subnet: CIDR-Notation, z. B. "192.168.178.0/24"
        timeout: Timeout pro Host in Sekunden
        max_workers: Parallele Threads

    Yields:
        Tuple (ip, is_online, hostname, mac_address)
    """
    network = ipaddress.IPv4Network(subnet, strict=False)
    local_ip = get_local_ip()

    # Bei /31 und /32 direkt verwenden, sonst alle Hosts
    hosts = list(network.hosts()) if network.prefixlen < 31 else [network.network_address]

    # Local IP immer inkludieren
    if local_ip not in [str(h) for h in hosts] and ipaddress.IPv4Address(local_ip) in network:
        hosts.append(ipaddress.IPv4Address(local_ip))

    def _check(ip_str: str) -> tuple[str, bool, str, str]:
        is_online = _ping_host(ip_str, timeout)
        hostname = ""
        mac = ""
        if is_online:
            hostname = _resolve_hostname(ip_str)
            mac = _get_arp_mac(ip_str)
        return (ip_str, is_online, hostname, mac)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check, str(host)): str(host) for host in hosts}
        for future in as_completed(futures):
            ip, is_online, hostname, mac = future.result()
            yield (ip, is_online, hostname, mac)
