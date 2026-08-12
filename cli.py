"""CLI: Kommandozeilen-Schnittstelle mit typer + rich."""

from __future__ import annotations

import json
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .models import Device, DeviceType, PrinterStatus, ScanResult
from .discovery import get_local_subnet, scan_network
from .ports import scan_ports
from .mdns_probe import discover_mdns_devices
from .snmp_probe import probe_snmp
from .ipp_probe import probe_ipp
from .http_probe import probe_http
from .classify import classify_device

app = typer.Typer(
    help="Network Printer Inspector - Scannt Netzwerk und liest Druckerdaten aus.",
    no_args_is_help=True,
)
console = Console()

PRINTER_STATUS_COLORS = {
    PrinterStatus.IDLE: "green",
    PrinterStatus.PRINTING: "yellow",
    PrinterStatus.STOPPED: "red",
    PrinterStatus.ERROR: "red",
    PrinterStatus.OFFLINE: "dim",
    PrinterStatus.UNKNOWN: "dim",
}

DEVICE_TYPE_COLORS = {
    DeviceType.PRINTER: "cyan",
    DeviceType.ROUTER: "magenta",
    DeviceType.COMPUTER: "blue",
    DeviceType.PHONE: "green",
    DeviceType.IOT: "yellow",
    DeviceType.OTHER: "white",
    DeviceType.UNKNOWN: "dim",
}


@app.command()
def scan(
    subnet: str = typer.Option(
        None, "--subnet", "-s", help="Subnetz in CIDR-Notation (z. B. 192.168.178.0/24). Auto-Erkennung wenn nicht angegeben."
    ),
    timeout: float = typer.Option(1.0, "--timeout", "-t", help="Timeout pro Host in Sekunden."),
    community: str = typer.Option("public", "--community", "-c", help="SNMP Community String."),
    mdns_timeout: float = typer.Option(5.0, "--mdns-timeout", help="mDNS-Suchdauer in Sekunden."),
    output: Path = typer.Option(None, "--output", "-o", help="JSON-Datei für Ergebnisse."),
    csv_output: Path = typer.Option(None, "--csv", help="CSV-Datei für Drucker-Übersicht."),
    printers_only: bool = typer.Option(False, "--printers-only", "-p", help="Nur Drucker anzeigen."),
    no_snmp: bool = typer.Option(False, "--no-snmp", help="SNMP-Abfragen überspringen."),
    no_ipp: bool = typer.Option(False, "--no-ipp", help="IPP-Abfragen überspringen."),
    no_http: bool = typer.Option(False, "--no-http", help="HTTP-Abfragen überspringen."),
    no_mdns: bool = typer.Option(False, "--no-mdns", help="mDNS-Abfragen überspringen."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Detaillierte Ausgabe."),
) -> None:
    """Scannt das Netzwerk nach Geräten und Druckern."""
    # Subnetz bestimmen
    if subnet is None:
        subnet = get_local_subnet()
        console.print(f"[dim]Subnetz automatisch erkannt: {subnet}[/dim]")
    else:
        console.print(f"Subnetz: {subnet}")

    result = ScanResult(subnet=subnet)
    start_time = time.time()

    # Phase 1: Netzwerk-Scan
    console.print("\n[bold cyan]Phase 1:[/] Netzwerk wird gescannt...")
    online_hosts: list[tuple[str, str, str]] = []  # (ip, hostname, mac)
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Suche nach aktiven Geräten...", total=None)
        for ip, is_online, hostname, mac in scan_network(subnet, timeout=timeout):
            result.total_hosts_scanned += 1
            if is_online:
                result.total_hosts_online += 1
                online_hosts.append((ip, hostname, mac))
                if verbose:
                    console.print(f"  [green]+[/green] {ip:<16} {hostname or '(kein Name)'} {mac}")

    console.print(f"  {result.total_hosts_online} von {result.total_hosts_scanned} Hosts online")

    # Phase 2: mDNS-Scan (parallel zu Port-Scan)
    mdns_devices: dict = {}
    if not no_mdns:
        console.print("\n[bold cyan]Phase 2:[/] mDNS/Bonjour-Dienste werden gesucht...")
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            progress.add_task("Suche nach mDNS-Druckern...", total=None)
            mdns_devices = discover_mdns_devices(timeout=mdns_timeout)
        console.print(f"  {len(mdns_devices)} mDNS-Dienste gefunden")

    # Phase 3: Port-Scan + Drucker-Abfragen
    console.print("\n[bold cyan]Phase 3:[/] Ports werden gescannt und Druckerdaten abgefragt...")
    for ip, hostname, mac in online_hosts:
        device = Device(
            ip_address=ip,
            hostname=hostname,
            mac_address=mac,
        )

        # mDNS-Daten
        mdns_is_printer = ip in mdns_devices
        if mdns_is_printer:
            device.mdns_data = mdns_devices[ip]
            device.notes.append(f"mDNS: {mdns_devices[ip].service_type}")

        # Port-Scan
        device.ports = scan_ports(ip, timeout=timeout)

        # Drucker-Daten abfragen (nur bei Druckerverdacht)
        has_printer_ports = any(p.open for p in device.ports if p.port in {631, 9100, 515})
        has_snmp = any(p.open for p in device.ports if p.port == 161)
        has_http = any(p.open for p in device.ports if p.port in {80, 443})

        if (has_printer_ports or mdns_is_printer or has_snmp):
            # SNMP
            if not no_snmp and has_snmp:
                if verbose:
                    console.print(f"  [dim]SNMP-Abfrage: {ip}[/]")
                device.snmp_data = probe_snmp(ip, community=community, timeout=timeout * 2)

            # IPP
            if not no_ipp:
                ipp_port_open = any(p.open for p in device.ports if p.port == 631)
                if ipp_port_open:
                    if verbose:
                        console.print(f"  [dim]IPP-Abfrage: {ip}[/]")
                    device.ipp_data = probe_ipp(ip, timeout=timeout * 3)

            # HTTP
            if not no_http and has_http:
                if verbose:
                    console.print(f"  [dim]HTTP-Abfrage: {ip}[/]")
                device.http_data = probe_http(ip, timeout=timeout * 3)

        # Klassifizieren
        device = classify_device(device, mdns_is_printer=mdns_is_printer)

        if device.is_printer:
            result.total_printers_found += 1
            console.print(f"  [cyan bold]DRUCKER[/] {ip:<16} {device.hostname or ''}")

        result.devices.append(device)

    elapsed = time.time() - start_time
    console.print(f"\n[bold green]Scan abgeschlossen in {elapsed:.1f}s[/]")
    console.print(f"  Geräte gefunden: {result.total_hosts_online}")
    console.print(f"  Drucker gefunden: {result.total_printers_found}")

    # Ausgabe: Tabelle
    console.print()
    _print_device_table(result, printers_only, verbose)

    # Drucker-Details
    printers = [d for d in result.devices if d.is_printer]
    if printers:
        console.print()
        _print_printer_details(printers, verbose)

    # JSON speichern
    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"\n[green]JSON gespeichert:[/] {output}")

    # CSV speichern
    if csv_output and printers:
        _save_csv(printers, csv_output)
        console.print(f"[green]CSV gespeichert:[/] {csv_output}")


@app.command()
def info() -> None:
    """Zeigt Info zum lokalen Netzwerk an."""
    from .discovery import get_local_ip
    subnet = get_local_subnet()
    local_ip = get_local_ip()
    console.print(f"[bold]Lokale IP:[/] {local_ip}")
    console.print(f"[bold]Subnetz:[/] {subnet}")


def _print_device_table(result: ScanResult, printers_only: bool, verbose: bool) -> None:
    """Gibt eine Gerätetabelle aus."""
    table = Table(title="Gefundene Geräte")
    table.add_column("IP", style="white")
    table.add_column("Hostname", style="dim")
    table.add_column("Typ", style="bold")
    table.add_column("MAC", style="dim")
    table.add_column("Offene Ports", style="green")
    if verbose:
        table.add_column("Dienste", style="dim")

    for dev in result.devices:
        if not dev.is_online:
            continue
        if printers_only and not dev.is_printer:
            continue

        open_ports = ", ".join(str(p.port) for p in dev.ports if p.open) or "-"
        type_color = DEVICE_TYPE_COLORS.get(dev.device_type, "white")
        type_str = f"[{type_color}]{dev.device_type.value}[/{type_color}]"

        row = [
            dev.ip_address,
            dev.hostname or "-",
            type_str,
            dev.mac_address or "-",
            open_ports,
        ]
        if verbose:
            services = ", ".join(p.service for p in dev.ports if p.open) or "-"
            row.append(services)

        table.add_row(*row)

    console.print(table)


def _print_printer_details(printers: list[Device], verbose: bool) -> None:
    """Gibt detaillierte Druckerinformationen aus."""
    console.print("[bold cyan]Drucker-Details[/]")
    console.print()

    for p in printers:
        status_color = PRINTER_STATUS_COLORS.get(p.printer_status, "white")
        console.print(f"[bold cyan]═══ {p.ip_address} ═══[/]")
        console.print(f"  Status:      [{status_color}]{p.printer_status.value}[/{status_color}]")
        console.print(f"  Hostname:    {p.hostname or '-'}")
        console.print(f"  MAC:         {p.mac_address or '-'}")

        if p.mdns_data:
            console.print(f"  [bold]mDNS:[/]")
            console.print(f"    Dienst:    {p.mdns_data.service_type}")
            console.print(f"    Name:      {p.mdns_data.service_name}")
            if p.mdns_data.hostname:
                console.print(f"    Hostname:  {p.mdns_data.hostname}")
            if p.mdns_data.properties:
                console.print(f"    Props:     {len(p.mdns_data.properties)} Eigenschaften")

        if p.snmp_data:
            console.print(f"  [bold]SNMP:[/]")
            console.print(f"    Modell:    {p.snmp_data.sys_descr or '-'}")
            console.print(f"    Name:      {p.snmp_data.sys_name or '-'}")
            console.print(f"    Standort:  {p.snmp_data.sys_location or '-'}")
            console.print(f"    Kontakt:   {p.snmp_data.sys_contact or '-'}")
            console.print(f"    Uptime:    {p.snmp_data.sys_uptime or '-'}")
            if p.snmp_data.serial_number:
                console.print(f"    Seriennr.: {p.snmp_data.serial_number}")
            if p.snmp_data.total_pages_printed is not None:
                console.print(f"    Gedruckt:  {p.snmp_data.total_pages_printed:,} Seiten")
            if p.snmp_data.printer_marker_level:
                console.print(f"    [bold]Füllstände:[/]")
                for m in p.snmp_data.printer_marker_level:
                    pct = f"{m['percent']}%" if m.get("percent") is not None else "?"
                    bar = _progress_bar(m.get("percent"))
                    console.print(f"      {m['description']:<30} {bar} {pct}")

        if p.ipp_data:
            console.print(f"  [bold]IPP:[/]")
            console.print(f"    Modell:    {p.ipp_data.printer_make_and_model or '-'}")
            console.print(f"    Name:      {p.ipp_data.printer_name or '-'}")
            console.print(f"    Status:    {p.ipp_data.printer_state or '-'}")
            if p.ipp_data.printer_state_reasons:
                console.print(f"    Gründe:    {', '.join(p.ipp_data.printer_state_reasons)}")
            if p.ipp_data.queued_job_count is not None:
                console.print(f"    Wartend:   {p.ipp_data.queued_job_count} Jobs")
            if p.ipp_data.printer_is_accepting_jobs is not None:
                console.print(f"    Nimmt Jobs: {'Ja' if p.ipp_data.printer_is_accepting_jobs else 'Nein'}")
            if p.ipp_data.color_supported is not None:
                console.print(f"    Farbe:     {'Ja' if p.ipp_data.color_supported else 'Nein'}")
            if p.ipp_data.duplex_supported is not None:
                console.print(f"    Duplex:    {'Ja' if p.ipp_data.duplex_supported else 'Nein'}")
            if p.ipp_data.pages_per_minute:
                console.print(f"    Geschw.:   {p.ipp_data.pages_per_minute} Seiten/Min")
            if p.ipp_data.media_supported:
                console.print(f"    Formate:   {', '.join(p.ipp_data.media_supported[:10])}")

        if p.http_data:
            console.print(f"  [bold]HTTP:[/]")
            console.print(f"    Titel:     {p.http_data.title or '-'}")
            console.print(f"    Server:    {p.http_data.server_header or '-'}")
            console.print(f"    Status:    {p.http_data.status_code or '-'}")

        console.print()


def _progress_bar(percent: int | None, width: int = 20) -> str:
    """Erzeugt einen Fortschrittsbalken."""
    if percent is None:
        return "[dim]" + "?" * width + "[/dim]"
    filled = int(width * max(0, min(100, percent)) / 100)
    # Farbe basierend auf Füllstand
    if percent > 50:
        color = "green"
    elif percent > 20:
        color = "yellow"
    else:
        color = "red"
    bar = f"[{color}]" + "█" * filled + "[/{color}]" + "[dim]" + "░" * (width - filled) + "[/dim]"
    return bar


def _save_csv(printers: list[Device], path: Path) -> None:
    """Speichert Drucker-Übersicht als CSV."""
    import csv

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "IP", "Hostname", "MAC", "Status",
            "Modell (SNMP)", "Modell (IPP)", "Seriennummer",
            "Gedruckte Seiten", "Farbe", "Duplex",
            "Füllstände", "Offene Ports",
        ])

        for p in printers:
            model_snmp = p.snmp_data.sys_descr if p.snmp_data else ""
            model_ipp = p.ipp_data.printer_make_and_model if p.ipp_data else ""
            serial = p.snmp_data.serial_number if p.snmp_data else ""
            pages = p.snmp_data.total_pages_printed if p.snmp_data else ""
            color = p.ipp_data.color_supported if p.ipp_data else ""
            duplex = p.ipp_data.duplex_supported if p.ipp_data else ""

            supplies = ""
            if p.snmp_data and p.snmp_data.printer_marker_level:
                parts = []
                for m in p.snmp_data.printer_marker_level:
                    pct = f"{m['percent']}%" if m.get("percent") is not None else "?"
                    parts.append(f"{m['description']}: {pct}")
                supplies = "; ".join(parts)

            ports = ", ".join(str(p2.port) for p2 in p.ports if p2.open)

            writer.writerow([
                p.ip_address, p.hostname or "", p.mac_address or "",
                p.printer_status.value,
                model_snmp, model_ipp, serial,
                pages, color, duplex,
                supplies, ports,
            ])


if __name__ == "__main__":
    app()
