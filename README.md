# Netzwerk-Anonymisierer (`anon.ps1` & `anonymisierer.html`)

Offline-Werkzeug zum konsistenten Anonymisieren von Netzwerk-Logs, Show-Techs, Konfigurationsdateien und JSON-Dumps (Aruba AOS-CX/AOS-S, Dell Enterprise SONiC, Dell OS10, Cisco IOS/NX-OS, FortiGate, Sophos XG/SFOS, Linux-Syslog, Windows-Eventlogs), bevor diese an eine KI oder externe Experten übergeben werden.

Beide Varianten verwenden exakt dasselbe Regelschema ([`anon-regeln.json`](./anon-regeln.json)) und liefern identische Ausgaben (sowohl bei LF- als auch bei CRLF-Dateien):
1. **Variante A – PowerShell-CLI ([`anon.ps1`](./anon.ps1)):** Läuft auf Windows (Admin-VM) unter Windows PowerShell 5.1 (sowie PowerShell 7+) ohne Python, ohne externe Module und ohne Internetverbindung. Dank eingebetteter C#-Engine (mit 5-Sekunden-Regex-Timeout je Ausdruck) werden auch große Dateien (bis 50 MB) und Show-Tech-Archive mit tausenden Dateien schnell verarbeitet.
2. **Variante B – Eigenständige Browser-App ([`anonymisierer.html`](./anonymisierer.html)):** Eine einzige HTML-Datei (HTML, CSS, JS inkl. eingebettetem ZIP/TAR.GZ-Codec), die per Doppelklick in Edge oder Chrome komplett offline im Arbeitsspeicher (RAM) läuft und durch eine strikte `Content-Security-Policy` (`default-src 'none'; connect-src 'none'`) jeglichen Netzwerkverkehr unterbindet.

---

## Inhaltsverzeichnis
1. [Installation & Bereitstellung](#1-installation--bereitstellung)
2. [Empfohlener Arbeitsablauf (6 Schritte)](#2-empfohlener-arbeitsablauf-6-schritte)
3. [Bedienung Variante A: PowerShell (`anon.ps1`)](#3-bedienung-variante-a-powershell-anonps1)
4. [Bedienung Variante B: Offline-Browser-App (`anonymisierer.html`)](#4-bedienung-variante-b-offline-browser-app-anonymisiererhtml)
5. [Lokale Regeldatei (`anon-regeln.lokal.json`) auf der Admin-VM pflegen](#5-lokale-regeldatei-anon-regelnlokaljson-auf-der-admin-vm-pflegen)
6. [Sicherheitskonzept & Grenzen des Werkzeugs](#6-sicherheitskonzept--grenzen-des-werkzeugs)
7. [Tests ausführen](#7-tests-ausführen)
8. [Eingebettete Komponenten & Lizenzen](#8-eingebettete-komponenten--lizenzen)

---

## 1. Installation & Bereitstellung

Kopieren Sie die drei Hauptdateien auf Ihre Admin-VM (z. B. nach `C:\Tools\anonymisierer\`):
- `anon.ps1`
- `anonymisierer.html`
- `anon-regeln.json` (Beispiel- und Basisregelwerk ohne echte Infrastrukturdaten)

Es wird keine Installation, kein Internetzugang und kein zusätzliches PowerShell-Modul benötigt.

> **Wichtiger Hinweis zur Trennung von Vorlage und echten Namen (`anon-regeln.lokal.json`):**
> Die mitgelieferte Datei `anon-regeln.json` dient als geteilte Vorlage und enthält ausschließlich synthetische Beispielwerte. Kopieren Sie diese Datei auf Ihrer Admin-VM nach **`anon-regeln.lokal.json`** und tragen Sie Ihre echten Gerätenamen, Firmennamen, internen Domains und Namensschema-Präfixe **ausschließlich in `anon-regeln.lokal.json`** ein. Geben Sie `anon-regeln.lokal.json` niemals weiter und laden Sie sie nirgendwo hoch!

---

## 2. Empfohlener Arbeitsablauf (6 Schritte)

```
[1. Sammeln] -> [2. Anonymisieren] -> [3. Prüfen (-Pruefen)] -> [4. Sichtprüfung] -> [5. Weitergabe] -> [6. Rückübersetzen]
```

1. **Sammeln:**
   Legen Sie die relevanten Konfigurationsdateien, Show-Tech-Ordner oder `.zip`/`.tar.gz`-Archive in einem lokalen Eingabeordner ab.
2. **Anonymisieren:**
   Starten Sie `anon.ps1` mit Ihrer lokalen Regeldatei `-Regeln .\anon-regeln.lokal.json` (oder laden Sie die lokale Regeldatei in `anonymisierer.html`).
   - Dateien mit UTF-8-BOM sowie UTF-16 LE/BE BOM (z. B. Windows-Eventlogs) werden automatisch anhand des BOM erkannt und immer als UTF-8 ohne BOM ausgegeben.
   - Auch alle Datei- und Ordnernamen im Ausgabepfad werden durch die Engine anonymisiert (z. B. `show-tech-rz1-sw-core01.txt` -> `show-tech-CORE-A.txt`).
   - Geheimnisse (Passwörter, Hashes, `ciphertext`, SNMP-Communities, PSKs, PEM-Blöcke) werden unwiderruflich durch `*****` entfernt.
   - Infrastrukturdaten (IPs mit netzerhaltendem Format `NET-1.H17/24`, MACs als `MAC-1`, Hostnamen als `HOST-1` bzw. feste Rollen wie `CORE-A` / `TOR-A`, VLAN-Namen und Beschreibungen als `TEXT-1`) werden über alle Dateien hinweg konsistent ersetzt.
   - Die Zuordnungstabelle wird **außerhalb** des Ausgabeordners unter `%LOCALAPPDATA%\Anon\Tabellen\` abgelegt (geschützt per Windows-ACL auf Ihren Benutzer sowie standardmäßig unter Windows mit DPAPI oder per `-MitPasswort` mit `ANON-AES256-2` verschlüsselt).
   - Der temporäre Entpack-Ordner `<Ausgabe>\_arbeit\` wird nach dem Lauf automatisch gelöscht.
3. **Prüfen (`-Pruefen`):**
   Nach jedem Lauf sucht der Prüfmodus automatisch in allen Ausgabedateien **und Dateipfaden** nach eventuell verbliebenen IPv4/IPv6-Adressen, MAC-Adressen, E-Mail-Adressen, Sperrbegriffen, Hashes oder langen Hex/Base64-Blobs.
   - Nur wenn **0 Treffer** vorliegen, lautet das Ergebnis **`SAUBER`** (Exit-Code `0`).
   - Werden Restfunde entdeckt (`RESTFUNDE_VORHANDEN`), beendet sich `anon.ps1` auch im Hauptlauf mit **Exit-Code `2`**. Ergänzen Sie in diesem Fall das fehlende Muster in Ihrer `anon-regeln.lokal.json` und starten Sie den Lauf erneut.
4. **Sichtprüfung (Pflichtschritt vor jeder Weitergabe!):**
   Prüfen Sie die anonymisierten Dateien in `<Ausgabe>\anonym\` (bzw. in der Side-by-Side-Vorschau von `anonymisierer.html`) stichprobenartig mit eigenen Augen – insbesondere ungewöhnliche Freitext-Kommentare, Debug-Ausgaben oder mehrzeilige Notizen.
5. **Weitergabe:**
   Geben Sie **ausschließlich** den Unterordner `<Ausgabe>\anonym\` (bzw. das heruntergeladene `anonym-ausgabe.zip`, das keine `bericht.json` enthält) an die KI oder den externen Experten weiter – niemals den Quellordner und niemals die Zuordnungstabelle!
6. **Rückübersetzen (`-Zurueck`):**
   Wenn die KI oder der Experte eine Diagnose oder Konfigurationsänderung mit Platzhaltern liefert (z. B. `Prüfen Sie auf CORE-A das VLAN auf Port Ethernet1/1/10 zu TOR-A mit IP NET-1.H2/24`), übersetzen Sie den Text lokal mit `-Zurueck` (bzw. im Reiter *„4. Rückübersetzen“* in `anonymisierer.html`) mithilfe Ihrer gespeicherten Zuordnungstabelle wieder in die echten Infrastrukturwerte zurück.

---

## 3. Bedienung Variante A: PowerShell (`anon.ps1`)

### Standardlauf (Ordner, Einzeldateien oder `.zip` / `.tar.gz`)
Unter Windows schützt `anon.ps1` neue Zuordnungstabellen standardmäßig mit **Windows DPAPI (`CurrentUser`)** plus NTFS-ACL:
```powershell
cd C:\Tools\anonymisierer

# Einzelne Datei oder ganzen Show-Tech-Ordner / Archiv anonymisieren:
.\anon.ps1 -Eingabe "C:\Faelle\Eingang\show-tech.tar.gz" `
           -Ausgabe "C:\Faelle\Ausgang" `
           -Regeln ".\anon-regeln.lokal.json"
```
- **Freigegebene Ausgabe:** `C:\Faelle\Ausgang\anonym\`
- **Bericht (mit anonymisierten Dateipfaden):** `C:\Faelle\Ausgang\bericht.json`
- **Zuordnungstabelle (getrennt, ACL- & DPAPI-geschützt):** `%LOCALAPPDATA%\Anon\Tabellen\tabelle-<Zeitstempel>.json`

### Mit Passwortverschlüsselung (`-MitPasswort`, Format `ANON-AES256-2`) oder Klartext (`-Unverschluesselt`)
Passwörter müssen **mindestens 12 Zeichen** lang sein und werden sicher per `Read-Host -AsSecureString` abgefragt (beim Neuanlegen zweimal zur Bestätigung). Das Format `ANON-AES256-2` leitet über `PBKDF2-SHA1` (600.000 Iterationen) einen Master-Key ab, trennt davon per `HMAC-SHA256` separate Schlüssel für AES-256-CBC (`"enc"`) und HMAC-SHA256 (`"mac"`) ab und sichert Header, Iterationszahl, Salt, IV und Ciphertext vor der Entschlüsselung in konstanter Zeit ab. Ältere `ANON-AES256-1`-Tabellen bleiben mit einer Warnung ladbar und werden beim nächsten Speichern automatisch auf `ANON-AES256-2` aktualisiert.
```powershell
# Mit eigenem Passwort (mind. 12 Zeichen, zweimalige verdeckte Abfrage):
.\anon.ps1 -Eingabe "C:\Faelle\Eingang" -Ausgabe "C:\Faelle\Ausgang" `
           -Regeln ".\anon-regeln.lokal.json" `
           -TabellenPfad "$env:LOCALAPPDATA\Anon\Tabellen\fall01.json" `
           -MitPasswort

# Explizit unverschlüsselte Ablage der Tabelle (nur wenn ausdrücklich gewünscht):
.\anon.ps1 -Eingabe "C:\Faelle\Eingang" -Ausgabe "C:\Faelle\Ausgang" `
           -Regeln ".\anon-regeln.lokal.json" `
           -Unverschluesselt
```

### Bestehende Zuordnungstabelle weiterverwenden (kein stiller Schutzverlust)
Wird eine verschlüsselte Tabelle (Passwort oder DPAPI) über `-Tabelle` geladen, merkt sich `anon.ps1` deren Schutzart und behält sie beim Speichern automatisch bei – selbst wenn `-MitPasswort` oder `-Dpapi` beim Folgelauf nicht erneut angegeben wurde:
```powershell
.\anon.ps1 -Eingabe "C:\Faelle\Nachlieferung.log" -Ausgabe "C:\Faelle\Ausgang2" `
           -Regeln ".\anon-regeln.lokal.json" `
           -Tabelle "$env:LOCALAPPDATA\Anon\Tabellen\fall01.json"
```

### Trockenlauf (`-Probe`) und reiner Prüfmodus (`-Pruefen`)
```powershell
# Trockenlauf: Zeigt nur Anzahl Ersetzungen je Kategorie, schreibt keine Dateien
.\anon.ps1 -Eingabe "C:\Faelle\Eingang" -Regeln ".\anon-regeln.lokal.json" -Probe

# Reiner Prüfmodus auf einem bereits anonymisierten Ordner (Exit-Code 0 = SAUBER, Exit-Code 2 = Restfunde)
.\anon.ps1 -Eingabe "C:\Faelle\Ausgang\anonym" -Regeln ".\anon-regeln.lokal.json" -Pruefen
```

### Rückübersetzen einer KI-Antwort (`-Zurueck`)
```powershell
.\anon.ps1 -Zurueck -Eingabe "C:\Faelle\ki-antwort.txt" `
           -Ausgabe "C:\Faelle\ki-antwort-echt.txt" `
           -Tabelle "$env:LOCALAPPDATA\Anon\Tabellen\fall01.json"
```

---

## 4. Bedienung Variante B: Offline-Browser-App (`anonymisierer.html`)

1. Öffnen Sie `anonymisierer.html` per Doppelklick in Microsoft Edge oder Google Chrome.
2. **Reiter „2. Regeldatei (JSON)“:**
   - Laden Sie vor dem Lauf Ihre lokale `anon-regeln.lokal.json` von der Festplatte.
3. **Reiter „1. Anonymisieren & Prüfen“:**
   - Ziehen Sie Dateien, Ordner oder `.zip`/`.tar.gz`-Archive in das Drag-&-Drop-Feld.
   - Klicken Sie auf **„Anonymisieren & Prüfen“**.
   - Prüfen Sie oben rechts das Banner (**`SAUBER (0 Treffer)`** in Grün oder Restfunde in Rot) sowie darunter die Gegenüberstellung **Original vs. Anonymisiert**.
   - Laden Sie mit **„Anonymisiertes ZIP herunterladen“** das Freigabe-ZIP herunter (enthält ausschließlich `anonym/...` mit anonymisierten Dateinamen, **ohne** `bericht.json`).
4. **Reiter „3. Zuordnungstabelle (AES-GCM)“:**
   - Geben Sie ein Passwort mit **mindestens 12 Zeichen** zweimal ein, um die Zuordnungstabelle verschlüsselt herunterzuladen.
   - Zum Laden einer verschlüsselten Tabelle tragen Sie das Passwort **vor** dem Auswählen der Datei in das verdeckte Passwortfeld (`type="password"`) ein (es wird kein `prompt()`-Dialog verwendet, damit das Passwort nicht im Klartext auf dem Bildschirm erscheint).
5. **Reiter „4. Rückübersetzen“:**
   - Fügen Sie die Antwort der KI ein und klicken Sie auf **„Jetzt rückübersetzen“**. Alles bleibt ausschließlich im RAM des Browsers.

---

## 5. Lokale Regeldatei (`anon-regeln.lokal.json`) auf der Admin-VM pflegen

Kopieren Sie `anon-regeln.json` nach `anon-regeln.lokal.json` und passen Sie dort folgende Bereiche an:

### A. Eigene Begriffe, Rollen & Domains (`eigeneBegriffe`)
Begriffe in `festeZuordnung` und `firmenUndStandorte` werden automatisch mit Namensgrenzen `(?<![A-Za-z0-9-])...(?![A-Za-z0-9-])` gesucht, sodass z. B. `"rz1-tor-01"` niemals versehentlich den Anfang von `"rz1-tor-010"` zu `"TOR-A0"` verfälscht:
```json
"eigeneBegriffe": {
  "festeZuordnung": {
    "rz1-sw-core01": "CORE-A",
    "rz2-sw-core02": "CORE-B",
    "rz1-tor-01": "TOR-A"
  },
  "firmenUndStandorte": [
    "Musterfirma GmbH",
    "Rechenzentrum-Nord",
    "Max Mustermann"
  ],
  "interneDomains": [
    "intern.musterfirma.de",
    "ad.firma.lan"
  ]
}
```

### B. Gerätenamen in Tabellen (`hostnamenMuster`)
Alle mehrzeiligen Muster verwenden `(?=\r?$)` am Zeilenende, damit sie sowohl bei LF- als auch bei Windows-CRLF-Dateien in .NET und JavaScript identisch greifen:
```json
"hostnamenMuster": [
  "(?im)^([ \\t]*(?:hostname|sysname|switchname|prompt)[ \\t]+)([A-Za-z0-9._-]{2,64})([ \\t]*)(?=\\r?$)",
  "(?im)^([ \\t]*(?:System Name|Device ID)[ \\t]*:[ \\t]*)([A-Za-z0-9._-]{2,64})([ \\t]*)(?=\\r?$)",
  "(?i)(\"(?:hostname|sys_name|device_name|switch_name)\"[ \\t]*:[ \\t]*\")([A-Za-z0-9._-]{2,64})(\")",
  "(?i)\\b((?:rz\\d|sv|sw|tsw|back|lwl)-[A-Za-z0-9-]+)\\b"
]
```

---

## 6. Sicherheitskonzept & Grenzen des Werkzeugs

1. **Die Zuordnungstabelle ist so vertraulich wie das Original:**
   Wer die Zuordnungstabelle besitzt, kann alle Platzhalter wieder in echte IP-Adressen, Hostnamen und Seriennummern umwandeln (ausgenommen Geheimnisse, da diese durch `*****` gelöscht wurden). Bewahren Sie die Tabelle daher immer getrennt und verschlüsselt auf.
2. **Regex-Timeouts (Variante A vs. Variante B):**
   In Variante A (`anon.ps1` / .NET) sind sämtliche regulären Ausdrücke mit einem harten `MatchTimeout` von **5 Sekunden** gegen katastrophales Backtracking (ReDoS) bei selbstgebauten Regeln abgesichert. In Variante B (`anonymisierer.html`) unterstützt die JavaScript-Engine (`RegExp`) des Browsers nativ **kein** Regex-Timeout; achten Sie beim Erweitern eigener Muster in `anon-regeln.lokal.json` daher auf eindeutige Begrenzungen ohne geschachtelte Quantifizierer.
3. **Netzwerk-Topologie und Struktur bleiben erkennbar:**
   Durch konsistente Platzhalter (`NET-1.H1/24`, `CORE-A`, `MAC-1`) bleibt die logische Struktur für die Fehlersuche erhalten.
4. **Freitext immer selbst sichten:**
   Unstrukturierter Freitext (z. B. ungewöhnliche Log-Meldungen, Skript-Kommentare ohne Schlüsselwort) kann Begriffe enthalten, die keiner bekannten Regel entsprechen. Eine manuelle Sichtprüfung vor der Weitergabe ist daher unverzichtbar.

---

## 7. Tests ausführen

Der Ordner `tests\` enthält **48 synthetische Test- und Grenzfälle** (`tests\faelle.json`), die automatisch sowohl als LF- als auch als CRLF-Variante geprüft werden, realistische Beispieldateien (`tests\beispiele\`), erwartete Referenzausgaben (`tests\erwartet\`) sowie dedizierte Tests für alle Sicherheits- und Randfälle.

- **PowerShell-Testsuite starten:**
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
  ```
- **Node.js-Testsuite starten (für `anonymisierer.html` & Paritätstest):**
  ```bash
  node tests/run-tests.js
  ```

---

## 8. Eingebettete Komponenten & Lizenzen

- **Lizenz des Projekts (`anon.ps1`, `anonymisierer.html`, `anon-regeln.json`):** noch offen.
- **ZIP- und TAR/GZIP-Verarbeitung in `anonymisierer.html`:** Direkt eingebetteter Minimal-Codec auf Basis der standardisierten Browser-APIs (`DecompressionStream`, `DataView`, `Uint8Array`, `WebCrypto API`) ohne externe Fremdbibliotheken.
