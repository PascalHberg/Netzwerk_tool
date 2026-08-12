"""SNMP-Probe: Liest Druckerdaten über SNMPv2c aus."""

from __future__ import annotations

import time
from typing import Any

from .models import SNMPData

# Wichtige SNMP-OIDs für Drucker
OIDS = {
    # SYS Group (SNMPv2-MIB)
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",

    # HOST-RESOURCES-MIB
    "hrDeviceDescr": "1.3.6.1.2.1.25.3.2.1.3.1",

    # Printer-MIB - Status
    "prtAuxiliarySheetStartupPage": "1.3.6.1.2.1.43.15.1.1.2.1",

    # Printer-MIB - Marker (Toner/Tinte)
    "prtMarkerLifeUnit": "1.3.6.1.2.1.43.10.1.1.5.1",        # Total printed pages
    "prtMarkerPowerOnCount": "1.3.6.1.2.1.43.10.1.1.4.1",   # Power-on count

    # Printer-MIB - Supply (Toner/Papier Füllstände)
    "prtMarkerSuppliesDescription": "1.3.6.1.2.1.43.11.1.1.6",
    "prtMarkerSuppliesMaxCapacity": "1.3.6.1.2.1.43.11.1.1.8",
    "prtMarkerSuppliesLevel": "1.3.6.1.2.1.43.11.1.1.9",
    "prtMarkerSuppliesType": "1.3.6.1.2.1.43.11.1.1.5",

    # Printer-MIB - Serial Number (herstellerspezifisch, oft unter Enterprise MIBs)
    # HP: 1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0
    # Brother: 1.3.6.1.4.1.2435.2.3.605.1.1.1.3.0
    # Lexmark: 1.3.6.1.4.1.641.2.1.2.1.3.0
}

# Bekannte Serial-Number-OIDs (herstellerspezifisch)
SERIAL_NUMBER_OIDS = [
    "1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0",        # HP
    "1.3.6.1.4.1.2435.2.3.605.1.1.1.3.0",         # Brother
    "1.3.6.1.4.1.641.2.1.2.1.3.0",                # Lexmark
    "1.3.6.1.4.1.1602.1.2.1.3.0",                # Canon
    "1.3.6.1.4.1.1347.43.5.1.1.13.0",             # Kyocera
    "1.3.6.1.4.1.367.3.2.1.2.1.4.0",              # Xerox
    "1.3.6.1.2.1.43.5.1.1.17.1",                  # Printer-MIB general serial
]


def _snmp_get(ip: str, oid: str, community: str, timeout: float, retries: int) -> Any:
    """Führt einen SNMP-GetRequest durch."""
    try:
        from pysnmp.hlapi import (
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            getCmd,
        )

        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # SNMPv2c
            UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            return None
        if error_status:
            return None

        for var_bind in var_binds:
            return var_bind[1]

    except ImportError:
        print("  [!] pysnmp nicht installiert - überspringe SNMP")
    except Exception:
        pass

    return None


def _snmp_walk(ip: str, oid: str, community: str, timeout: float, retries: int) -> list[tuple[str, Any]]:
    """Führt einen SNMP-Walk durch (für Tabellen wie Füllstände)."""
    results: list[tuple[str, Any]] = []
    try:
        from pysnmp.hlapi import (
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            nextCmd,
        )

        for response in nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            error_indication, error_status, error_index, var_binds = response
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                value = var_bind[1]
                results.append((oid_str, value))

    except Exception:
        pass

    return results


def _value_to_str(value: Any) -> str:
    """Konvertiert einen SNMP-Wert in einen String."""
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return repr(value)


def _value_to_int(value: Any) -> int | None:
    """Konvertiert einen SNMP-Wert in int."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def probe_snmp(
    ip: str,
    community: str = "public",
    timeout: float = 2.0,
    retries: int = 1,
) -> SNMPData | None:
    """Fragt Druckerdaten über SNMPv2c ab.

    Args:
        ip: Ziel-IP
        community: SNMP Community String (default: "public")
        timeout: SNMP-Timeout in Sekunden
        retries: Anzahl Wiederholungen

    Returns:
        SNMPData oder None wenn kein SNMP verfügbar
    """
    # Erst testen ob SNMP überhaupt antwortet
    test = _snmp_get(ip, OIDS["sysDescr"], community, timeout, retries)
    if test is None:
        return None

    data = SNMPData()
    data.sys_descr = _value_to_str(test)

    # Weitere SYS-Gruppe Werte
    data.sys_name = _value_to_str(_snmp_get(ip, OIDS["sysName"], community, timeout, retries))
    data.sys_location = _value_to_str(_snmp_get(ip, OIDS["sysLocation"], community, timeout, retries))
    data.sys_contact = _value_to_str(_snmp_get(ip, OIDS["sysContact"], community, timeout, retries))

    # Uptime formatieren
    uptime_raw = _value_to_int(_snmp_get(ip, OIDS["sysUpTime"], community, timeout, retries))
    if uptime_raw is not None:
        uptime_seconds = uptime_raw // 100  # centiseconds -> seconds
        days, rem = divmod(uptime_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        data.sys_uptime = f"{days}d {hours}h {minutes}m {seconds}s"

    # HR Device Description
    data.hr_device_desc = _value_to_str(_snmp_get(ip, OIDS["hrDeviceDescr"], community, timeout, retries))

    # Total pages printed
    pages = _value_to_int(_snmp_get(ip, OIDS["prtMarkerLifeUnit"], community, timeout, retries))
    if pages is not None and pages > 0:
        data.total_pages_printed = pages
    else:
        # Fallback: PowerOnCount
        pages = _value_to_int(_snmp_get(ip, OIDS["prtMarkerPowerOnCount"], community, timeout, retries))
        if pages is not None:
            data.total_pages_printed = pages

    # Füllstände (Toner/Tinte) über Walk
    descriptions = _snmp_walk(ip, OIDS["prtMarkerSuppliesDescription"], community, timeout, retries)
    max_caps = _snmp_walk(ip, OIDS["prtMarkerSuppliesMaxCapacity"], community, timeout, retries)
    levels = _snmp_walk(ip, OIDS["prtMarkerSuppliesLevel"], community, timeout, retries)

    for i, (desc_oid, desc_val) in enumerate(descriptions):
        desc = _value_to_str(desc_val).strip() if desc_val else ""
        if not desc:
            continue

        max_cap = _value_to_int(max_caps[i][1]) if i < len(max_caps) else None
        level = _value_to_int(levels[i][1]) if i < len(levels) else None

        # Berechne Prozent
        percent = None
        if max_cap is not None and level is not None and max_cap > 0:
            # Level -3 = unbekannt, -2 = eine Restmenge
            if level >= 0 and max_cap > 0:
                percent = round((level / max_cap) * 100)

        entry = {
            "description": desc,
            "max_capacity": max_cap,
            "current_level": level,
            "percent": percent,
        }
        data.printer_marker_level.append(entry)

    # Seriennummer
    for sn_oid in SERIAL_NUMBER_OIDS:
        sn = _value_to_str(_snmp_get(ip, sn_oid, community, timeout, retries))
        if sn and sn.strip() and sn.strip() != "0":
            data.serial_number = sn.strip()
            break

    return data
