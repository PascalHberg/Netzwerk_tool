"""Datenmodelle für Geräte und Drucker."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class DeviceType(str, Enum):
    UNKNOWN = "unknown"
    PRINTER = "printer"
    ROUTER = "router"
    COMPUTER = "computer"
    PHONE = "phone"
    IOT = "iot"
    OTHER = "other"


class PrinterStatus(str, Enum):
    UNKNOWN = "unknown"
    IDLE = "idle"
    PRINTING = "printing"
    STOPPED = "stopped"
    ERROR = "error"
    OFFLINE = "offline"


@dataclass
class PortInfo:
    """Information über einen offenen Port."""
    port: int
    protocol: str  # "tcp" oder "udp"
    service: str  # z. B. "http", "ipp", "jetdirect", "snmp"
    open: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "open": self.open,
        }


@dataclass
class SNMPData:
    """SNMP-abgefragte Druckerdaten."""
    sys_descr: str = ""
    sys_name: str = ""
    sys_location: str = ""
    sys_contact: str = ""
    sys_uptime: str = ""
    hr_device_desc: str = ""
    printer_marker_level: list[dict[str, Any]] = field(default_factory=list)
    printer_status: str = ""
    total_pages_printed: int | None = None
    serial_number: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sys_descr": self.sys_descr,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "sys_contact": self.sys_contact,
            "sys_uptime": self.sys_uptime,
            "hr_device_desc": self.hr_device_desc,
            "printer_marker_level": self.printer_marker_level,
            "printer_status": self.printer_status,
            "total_pages_printed": self.total_pages_printed,
            "serial_number": self.serial_number,
        }


@dataclass
class IPPData:
    """IPP-abgefragte Druckerdaten."""
    printer_name: str = ""
    printer_state: str = ""
    printer_state_reasons: list[str] = field(default_factory=list)
    printer_make_and_model: str = ""
    printer_uri_supported: list[str] = field(default_factory=list)
    copies_default: int | None = None
    pages_per_minute: int | None = None
    media_supported: list[str] = field(default_factory=list)
    color_supported: bool | None = None
    duplex_supported: bool | None = None
    printer_is_accepting_jobs: bool | None = None
    queued_job_count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "printer_name": self.printer_name,
            "printer_state": self.printer_state,
            "printer_state_reasons": self.printer_state_reasons,
            "printer_make_and_model": self.printer_make_and_model,
            "printer_uri_supported": self.printer_uri_supported,
            "copies_default": self.copies_default,
            "pages_per_minute": self.pages_per_minute,
            "media_supported": self.media_supported,
            "color_supported": self.color_supported,
            "duplex_supported": self.duplex_supported,
            "printer_is_accepting_jobs": self.printer_is_accepting_jobs,
            "queued_job_count": self.queued_job_count,
        }


@dataclass
class MDNSData:
    """mDNS/Bonjour-abgefragte Daten."""
    service_type: str = ""
    service_name: str = ""
    hostname: str = ""
    port: int | None = None
    properties: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_type": self.service_type,
            "service_name": self.service_name,
            "hostname": self.hostname,
            "port": self.port,
            "properties": self.properties,
        }


@dataclass
class HTTPData:
    """HTTP-abgefragte Web-Interface-Daten."""
    title: str = ""
    server_header: str = ""
    status_code: int | None = None
    redirect_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "server_header": self.server_header,
            "status_code": self.status_code,
            "redirect_url": self.redirect_url,
        }


@dataclass
class Device:
    """Repräsentiert ein gefundenes Netzwerkgerät."""
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    ports: list[PortInfo] = field(default_factory=list)
    is_printer: bool = False
    is_online: bool = True
    response_time_ms: float | None = None
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    snmp_data: SNMPData | None = None
    ipp_data: IPPData | None = None
    mdns_data: MDNSData | None = None
    http_data: HTTPData | None = None
    printer_status: PrinterStatus = PrinterStatus.UNKNOWN
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "device_type": self.device_type.value,
            "ports": [p.to_dict() for p in self.ports],
            "is_printer": self.is_printer,
            "is_online": self.is_online,
            "response_time_ms": self.response_time_ms,
            "discovered_at": self.discovered_at,
            "snmp_data": self.snmp_data.to_dict() if self.snmp_data else None,
            "ipp_data": self.ipp_data.to_dict() if self.ipp_data else None,
            "mdns_data": self.mdns_data.to_dict() if self.mdns_data else None,
            "http_data": self.http_data.to_dict() if self.http_data else None,
            "printer_status": self.printer_status.value,
            "notes": self.notes,
        }


@dataclass
class ScanResult:
    """Gesamtergebnis eines Scans."""
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    subnet: str = ""
    total_hosts_scanned: int = 0
    total_hosts_online: int = 0
    total_printers_found: int = 0
    devices: list[Device] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_time": self.scan_time,
            "subnet": self.subnet,
            "total_hosts_scanned": self.total_hosts_scanned,
            "total_hosts_online": self.total_hosts_online,
            "total_printers_found": self.total_printers_found,
            "devices": [d.to_dict() for d in self.devices],
        }
