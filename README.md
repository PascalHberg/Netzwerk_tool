# Netzwerk_tool — Network Printer Inspector

Netzwerk_tool scannt ein lokales Subnetz, erkennt Drucker und liest verfügbare Metadaten über SNMP, IPP, mDNS und HTTP aus. Zielgruppe sind Netzwerk‑Administratoren oder Techniker, die schnell eine Inventur von Druckern im Netz erstellen möchten.

## Features
- Schneller paralleler Netzwerkscan im Subnetz
- Automatische Drucker‑Erkennung (Ports, mDNS, Dienste)
- Auslesen von SNMP, IPP, mDNS/Bonjour und HTTP‑Metadaten
- Export als JSON und CSV
- Schöne Konsolen‑Ausgabe (Rich)
- Statische Web‑Viewer (GitHub Pages) zum einfachen Betrachten von Scan‑Ergebnissen

## Was zu tun ist (kein Python notwendig)
1. Öffne die Projekt‑Seite (GitHub Pages), z. B.:
   `https://PascalHberg.github.io/Netzwerk_tool/`
2. Auf der Seite: "Upload JSON/CSV" → wähle eine zuvor erzeugte Scan‑Datei (oder eine Beispiel‑Datei).
3. Suche, filtere (z. B. "nur Drucker") und exportiere gefilterte Ergebnisse als JSON/CSV.
Hinweis: Die Viewer‑Seite läuft vollständig im Browser — es werden keine Daten an einen Server gesendet.

---

## Schnellstart für Leute, die lokal scannen wollen 
Diese Schritte sind nur nötig, wenn du auf deinem Rechner selbst einen Scan durchführen willst.

1. Virtuelle Umgebung:  (Empfohlen)
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
