"""Classifier: Klassifiziert Geräte anhand von Ports, mDNS und Diensten."""

from __future__ import annotations

from .models import Device, DeviceType, PortInfo, PrinterStatus
from .ports import STRONG_PRINTER_PORTS


def classify_device(
    device: Device,
    mdns_is_printer: bool = False,
) -> Device:
    """Klassifiziert ein Gerät als Drucker oder anderen Typ.

    Args:
        device: Das zu klassifizierende Device
        mdns_is_printer: Ob mDNS einen Drucker-Dienst gemeldet hat

    Returns:
        Aktualisiertes Device mit device_type und is_printer
    """
    open_ports: set[int] = {p.port for p in device.ports if p.open}
    open_services: set[str] = {p.service for p in device.ports if p.open}

    # Drucker-Indikatoren
    printer_score = 0

    # Starke Indikatoren: IPP, JetDirect, LPD
    if open_ports & STRONG_PRINTER_PORTS:
        printer_score += 3

    # mDNS meldet Drucker-Dienst
    if mdns_is_printer:
        printer_score += 2

    # SNMP vorhanden + HTTP
    if "snmp" in open_services and ("http" in open_services or "https" in open_services):
        printer_score += 1

    # SNMP-Daten mit Drucker-Infos
    if device.snmp_data and device.snmp_data.printer_marker_level:
        printer_score += 2

    # IPP-Daten vorhanden
    if device.ipp_data and (device.ipp_data.printer_make_and_model or device.ipp_data.printer_name):
        printer_score += 2

    # Klassifizierung
    if printer_score >= 2:
        device.is_printer = True
        device.device_type = DeviceType.PRINTER
        device.printer_status = _determine_printer_status(device)
    else:
        # Andere Klassifizierung
        if "ssh" in open_services:
            device.device_type = DeviceType.COMPUTER
        elif "netbios-ssn" in open_services or "microsoft-ds" in open_services:
            device.device_type = DeviceType.COMPUTER
        elif "http" in open_services or "https" in open_services:
            # Könnte Router, IoT, oder Computer sein
            if device.http_data and device.http_data.server_header:
                server = device.http_data.server_header.lower()
                if "router" in server or "mikrotik" in server or "tp-link" in server or "fritz" in server:
                    device.device_type = DeviceType.ROUTER
                elif any(brand in server for brand in ["apache", "nginx", "iis"]):
                    device.device_type = DeviceType.OTHER
                else:
                    device.device_type = DeviceType.IOT
            else:
                device.device_type = DeviceType.OTHER
        elif "snmp" in open_services:
            device.device_type = DeviceType.ROUTER
        else:
            device.device_type = DeviceType.UNKNOWN

    return device


def _determine_printer_status(device: Device) -> PrinterStatus:
    """Bestimmt den Drucker-Status aus IPP- und SNMP-Daten."""
    # IPP hat Priorität
    if device.ipp_data:
        state = device.ipp_data.printer_state.lower()
        if state == "idle":
            return PrinterStatus.IDLE
        elif state == "processing":
            return PrinterStatus.PRINTING
        elif state == "stopped":
            return PrinterStatus.STOPPED
        elif state in ("error", "error-state"):
            return PrinterStatus.ERROR

    # SNMP Fallback
    if device.snmp_data:
        if device.snmp_data.printer_status:
            status = device.snmp_data.printer_status.lower()
            if "idle" in status:
                return PrinterStatus.IDLE
            elif "printing" in status:
                return PrinterStatus.PRINTING
            elif "error" in status:
                return PrinterStatus.ERROR

    return PrinterStatus.UNKNOWN
