# Netzwerk-Anonymisierer (`anon.ps1` & `anonymisierer.html`) + Read-Only Switch-Sammler (`switch-sammler.ps1`)

Offline-Werkzeug zum konsistenten Sammeln und Anonymisieren von Netzwerk-Logs, Show-Techs, Konfigurationsdateien und JSON-Dumps (Aruba AOS-CX/AOS-S, HPE Comware, Dell Enterprise SONiC, Dell OS10, MikroTik RouterOS v6/v7, Cisco IOS/NX-OS, FortiGate, Sophos XG/SFOS, Linux-Syslog, Windows-Eventlogs), bevor diese an eine KI oder externe Experten übergeben werden.

Beide Anonymisierer-Varianten verwenden exakt dasselbe Regelschema ([`anon-regeln.json`](./anon-regeln.json)) und liefern identische Ausgaben (sowohl bei LF- als auch bei CRLF-Dateien):
1. **Variante A – PowerShell-CLI ([`anon.ps1`](./anon.ps1)):** Läuft auf Windows (Admin-VM) unter Windows PowerShell 5.1 (sowie PowerShell 7+) ohne Python, ohne externe Module und ohne Internetverbindung. Dank eingebetteter C#-Engine (mit 5-Sekunden-Regex-Timeout je Ausdruck) werden auch große Dateien (bis 50 MB) und Show-Tech-Archive mit tausenden Dateien schnell verarbeitet.
2. **Variante B – Eigenständige Browser-App ([`anonymisierer.html`](./anonymisierer.html)):** Eine einzige HTML-Datei (HTML, CSS, JS inkl. eingebettetem ZIP/TAR.GZ-Codec), die per Doppelklick in Edge oder Chrome komplett offline im Arbeitsspeicher (RAM) läuft und durch eine strikte `Content-Security-Policy` (`default-src 'none'; connect-src 'none'`) jeglichen Netzwerkverkehr unterbindet.
3. **Read-Only Switch-Sammler ([`switch-sammler.ps1`](./switch-sammler.ps1)):** Sammelt ausschließlich lesende Diagnose- und Konfigurationsdaten per SSH anhand einer harten 2-Stufen-Allowlist pro Plattform-Profil und übergibt sie optional direkt an `anon.ps1`.

---

## Inhaltsverzeichnis
1. [Installation & Bereitstellung](#1-installation--bereitstellung)
2. [Empfohlener Arbeitsablauf (6 Schritte)](#2-empfohlener-arbeitsablauf-6-schritte)
3. [Bedienung Switch-Sammler (`switch-sammler.ps1`)](#3-bedienung-switch-sammler-switch-sammlerps1)
4. [Bedienung Variante A: PowerShell (`anon.ps1`)](#4-bedienung-variante-a-powershell-anonps1)
5. [Bedienung Variante B: Offline-Browser-App (`anonymisierer.html`)](#5-bedienung-variante-b-offline-browser-app-anonymisiererhtml)
6. [Lokale Regeldatei (`anon-regeln.lokal.json`) auf der Admin-VM pflegen](#6-lokale-regeldatei-anon-regelnlokaljson-auf-der-admin-vm-pflegen)
7. [Sicherheitskonzept & Grenzen des Werkzeugs](#7-sicherheitskonzept--grenzen-des-werkzeugs)
8. [Tests ausführen](#8-tests-ausführen)
9. [Eingebettete Komponenten & Lizenzen](#9-eingebettete-komponenten--lizenzen)

---

## 1. Installation & Bereitstellung

Kopieren Sie die Hauptdateien auf Ihre Admin-VM (z. B. nach `C:\Tools\anonymisierer\`):
- `anon.ps1`
- `anonymisierer.html`
- `anon-regeln.json` (Beispiel- und Basisregelwerk ohne echte Infrastrukturdaten)
- `switch-sammler.ps1` und `sammler-befehle.json` (Read-Only SSH-Sammler)

Es wird keine Installation, kein Internetzugang und kein zusätzliches PowerShell-Modul benötigt.

> **Wichtiger Hinweis zur Trennung von Vorlage und echten Namen (`anon-regeln.lokal.json`):**
> Die mitgelieferte Datei `anon-regeln.json` ist das Basisregelwerk und enthält ausschließlich synthetische Beispielwerte. Legen Sie auf Ihrer Admin-VM daneben eine **`anon-regeln.lokal.json`** an, die **nur Ihre Ergänzungen** enthält (echte Gerätenamen, Firmennamen, interne Domains, eigene Hostnamen-Muster), und übergeben Sie sie mit **`-LokaleRegeln`**. Die Basisregeln bleiben dabei aktiv. Geben Sie `anon-regeln.lokal.json` niemals weiter und laden Sie sie nirgendwo hoch!

---

## 2. Empfohlener Arbeitsablauf (6 Schritte)

```
[1. Sammeln] -> [2. Anonymisieren] -> [3. Prüfen (-Pruefen)] -> [4. Sichtprüfung] -> [5. Weitergabe] -> [6. Rückübersetzen]
```

1. **Sammeln:**
   Sammeln Sie die Switch-Ausgaben per `switch-sammler.ps1` (oder legen Sie bestehende Show-Tech-Ordner / `.zip`/`.tar.gz`-Archive in einem lokalen Eingabeordner ab).
2. **Anonymisieren:**
   Starten Sie `anon.ps1` mit Ihrer lokalen Regeldatei `-LokaleRegeln .\anon-regeln.lokal.json` (oder laden Sie die lokale Regeldatei in `anonymisierer.html` unter „Eigene Begriffe“). `-Regeln` bleibt für das Basisregelwerk (`anon-regeln.json`, Standard im Skriptordner).
   - Alle Dateien werden in zwei Durchläufen verarbeitet: Ein Hostname, der erst in Datei 3 erkannt wird, wird so auch in Datei 1 ersetzt.
   - Dateien mit UTF-8-BOM sowie UTF-16 LE/BE BOM (z. B. Windows-Eventlogs) werden automatisch anhand des BOM erkannt und immer als UTF-8 ohne BOM ausgegeben.
   - Auch alle Datei- und Ordnernamen im Ausgabepfad werden durch die Engine anonymisiert (z. B. `show-tech-rz1-sw-core01.txt` -> `show-tech-CORE-A.txt`).
   - Geheimnisse (Passwörter, Hashes, `ciphertext`, HPE Comware `password/key cipher|simple|hash`, MikroTik `private-key=`/`public-key=`, SNMP-Communities, PSKs, PEM-Blöcke) werden unwiderruflich durch `*****` entfernt.
   - Infrastrukturdaten (IPs mit netzerhaltendem Format `NET-1.H17/24`, MACs als `MAC-1`, Hostnamen als `HOST-1` bzw. feste Rollen wie `CORE-A` / `TOR-A`, VLAN-Namen und Beschreibungen als `TEXT-1`) werden über alle Dateien hinweg konsistent ersetzt.
   - Die Zuordnungstabelle wird **außerhalb** des Ausgabeordners unter `%LOCALAPPDATA%\Anon\Tabellen\` abgelegt (geschützt per Windows-ACL auf Ihren Benutzer sowie standardmäßig unter Windows mit DPAPI oder per `-MitPasswort` mit `ANON-AES256-2` verschlüsselt).
   - Archive werden **nicht** im Ausgabeordner entpackt, sondern unter `%LOCALAPPDATA%\Anon\arbeit\<zufall>\` (ACL nur Ihr Benutzer). Der Ordner wird nach jedem Lauf gelöscht, auch bei Fehler oder Abbruch (Strg+C). Reste eines hart beendeten Laufs werden beim nächsten Start entfernt.
   - Konsole und Fehlermeldungen enthalten **keine echten Werte**: Prüftreffer nur mit Kategorie, Datei und Zeile; Fehler nur mit laufender Nummer der Datei, Schritt und Fehlerart.
3. **Prüfen (`-Pruefen`):**
   Nach jedem Lauf sucht der Prüfmodus automatisch in allen Ausgabedateien **und Dateipfaden** nach eventuell verbliebenen IPv4/IPv6-Adressen, MAC-Adressen (alle Schreibweisen), E-Mail-Adressen, Sperrbegriffen, Hashes, langen Hex/Base64-Blobs, Hostnamen, Seriennummern, Benutzern, nicht ersetzten Freitext-Feldern und Tabellenspalten. Zusätzlich sucht er nach allen Originalwerten, die im Lauf erkannt wurden (Hosts, Seriennummern, Benutzer, Mail, Firmen), auch dort, wo sie direkt an `_` oder `-` grenzen (z. B. `Uplink_XY1-SW01_P56`).
   - Nur wenn **0 Treffer** vorliegen, lautet das Ergebnis **`SAUBER`** (Exit-Code `0`).
   - Werden Restfunde entdeckt (`RESTFUNDE_VORHANDEN`), beendet sich `anon.ps1` auch im Hauptlauf mit **Exit-Code `2`**. Ergänzen Sie in diesem Fall das fehlende Muster in Ihrer `anon-regeln.lokal.json` und starten Sie den Lauf erneut.
4. **Sichtprüfung (Pflichtschritt vor jeder Weitergabe!):**
   Prüfen Sie die anonymisierten Dateien in `<Ausgabe>\anonym\` (bzw. in der Side-by-Side-Vorschau von `anonymisierer.html`) stichprobenartig mit eigenen Augen – insbesondere ungewöhnliche Freitext-Kommentare, Debug-Ausgaben oder mehrzeilige Notizen.
5. **Weitergabe:**
   Geben Sie **ausschließlich** den Unterordner `<Ausgabe>\anonym\` (bzw. das heruntergeladene `anonym-ausgabe.zip`, das keine `bericht.json` enthält) an die KI oder den externen Experten weiter – niemals den Quellordner und niemals die Zuordnungstabelle!
6. **Rückübersetzen (`-Zurueck`):**
   Wenn die KI oder der Experte eine Diagnose oder Konfigurationsänderung mit Platzhaltern liefert (z. B. `Prüfen Sie auf CORE-A das VLAN auf Port Ethernet1/1/10 zu TOR-A mit IP NET-1.H2/24`), übersetzen Sie den Text lokal mit `-Zurueck` (bzw. im Reiter *„4. Rückübersetzen“* in `anonymisierer.html`) mithilfe Ihrer gespeicherten Zuordnungstabelle wieder in die echten Infrastrukturwerte zurück.

---

## 3. Bedienung Switch-Sammler (`switch-sammler.ps1`)

Der Sammler unterstützt die Profile `dell-sonic`, `dell-os10`, `aruba-aoscx`, `aruba-aoss`, `hpe-comware`, `mikrotik-routeros` und `cisco-ios`:
- **2-Stufen-Sicherheitsprüfung ohne Blocklist:**
  1. **Stufe 1 (Zeichensperre):** Verbietet `;`, `|`, `>`, `<`, `&`, `` ` ``, `$`, `\r`, `\n`.
  2. **Stufe 2 (Exakte Allowlist):** Jeder Befehl (und im Shell-Modus jede Zeile der temporären Befehlsdatei) muss 1:1 in der fest im Skript verdrahteten Allowlist des Profils stehen. `sammler-befehle.json` kann Befehle nur **abwählen**, niemals ergänzen.
- **Sitzungsmodell (`sitzungsModus`):**
  - `"shell"` (eine einzige SSH-Sitzung pro Gerät über stdin bzw. `plink -m <Befehlsdatei>`, Aufteilung anhand des Befehls-Echos/Prompts) für `aruba-aoscx`, `aruba-aoss`, `hpe-comware`, `dell-os10`, `dell-sonic` (Standard: Klish-CLI `sonic-cli`) und `cisco-ios`.
  - `"exec"` (ein Aufruf pro Befehl) für `dell-sonic` mit `-SonicClickCli` sowie `mikrotik-routeros`.
- **Hostkey-Pflicht (kein TOFU):**
  Das Pflichtfeld `hostkey` (sowie `sprungserverHostkey` bei Nutzung eines Sprungservers) enthält den vollständigen SSH Public Key (`"ssh-ed25519 AAAAC3Nza..."`). Daraus erzeugt `switch-sammler.ps1` pro Lauf eine temporäre `known_hosts` für `ssh.exe` und berechnet den `SHA256:...`-Fingerprint für `plink.exe -hostkey`.
- **MikroTik RouterOS v6/v7 & DHCP-Leases:**
  Führt zuerst `/system resource print without-paging` aus und wählt bei `6.x` automatisch `/export hide-sensitive`, bei `7.x` `/export terse`. Wird die Version nicht eindeutig als `6.x` oder `7.x` erkannt, wird **kein** `/export` ausgeführt und eine Warnung ausgegeben. `/ip dhcp-server lease print without-paging` liegt in `07_extra.txt` und ist standardmäßig abgewählt (Aktivierung nur per `-MitDhcpLeases`).
- **Fehlerbehandlung & Exit-Code `3`:**
  Teilausgaben bei Befehlsfehlern/Timeouts werden trotzdem gespeichert und in `_meta.json` vermerkt. Bei Login- oder Hostkey-Fehlern wird das betroffene Gerät sofort abgebrochen (kein Retry), der Lauf mit den übrigen Geräten fortgesetzt und am Ende mit **Exit-Code `3`** beendet.

```powershell
# Trockenlauf (zeigt für dell-sonic beide CLI-Varianten Klish + Click an):
.\switch-sammler.ps1 -Geraete "sw-core01" -Profil "dell-sonic" `
                     -Hostkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." -Trockenlauf

# Sammeln über Geräteliste (CSV/JSON) mit direkter Anonymisierung:
.\switch-sammler.ps1 -GeraeteDatei ".\geraete.csv" `
                     -AusgabeOrdner "C:\Faelle\Sammlung" `
                     -DirektAnonymisieren -RegelDatei ".\anon-regeln.lokal.json"
```

---

## 4. Bedienung Variante A: PowerShell (`anon.ps1`)

### Standardlauf (Ordner, Einzeldateien oder `.zip` / `.tar.gz`)
Unter Windows schützt `anon.ps1` neue Zuordnungstabellen standardmäßig mit **Windows DPAPI (`CurrentUser`)** plus NTFS-ACL:
```powershell
cd C:\Tools\anonymisierer

# Einzelne Datei oder ganzen Show-Tech-Ordner / Archiv anonymisieren:
.\anon.ps1 -Eingabe "C:\Faelle\Eingang\show-tech.tar.gz" `
           -Ausgabe "C:\Faelle\Ausgang" `
           -LokaleRegeln ".\anon-regeln.lokal.json"
```
- **Freigegebene Ausgabe:** `C:\Faelle\Ausgang\anonym\`
- **Bericht (mit anonymisierten Dateipfaden):** `C:\Faelle\Ausgang\bericht.json`
- **Zuordnungstabelle (getrennt, ACL- & DPAPI-geschützt):** `%LOCALAPPDATA%\Anon\Tabellen\tabelle-<Zeitstempel>.json`

### Mit Passwortverschlüsselung (`-MitPasswort`, Format `ANON-AES256-2`) oder Klartext (`-Unverschluesselt`)
Passwörter müssen **mindestens 12 Zeichen** lang sein und werden sicher per `Read-Host -AsSecureString` abgefragt (beim Neuanlegen zweimal zur Bestätigung). Das Passwort bleibt bis zur Schlüsselableitung ein `SecureString`; die Zwischenpuffer werden danach mit Nullen überschrieben.

Das Format `ANON-AES256-2` (gemeinsam für `anon.ps1` und `anonymisierer.html`):
- Schlüsselableitung **PBKDF2-SHA256** mit 600.000 Iterationen, wenn .NET Framework **4.7.2 oder neuer** vorhanden ist (Windows 10 ab 1803, Windows Server 2019). Auf älteren Systemen nutzt `anon.ps1` **PBKDF2-SHA1** und vermerkt das im Feld `kdf`. Eine im Browser erzeugte Tabelle (immer PBKDF2-SHA256) lässt sich auf solchen Systemen nicht laden; dann bricht `anon.ps1` mit einer Meldung ab.
- Aus dem Hauptschlüssel werden per HMAC-SHA256 getrennte Schlüssel für AES-256-CBC (`"enc"`) und HMAC-SHA256 (`"mac"`) gebildet; Kopf, Iterationszahl, Salt (16 Byte), IV (16 Byte) und Ciphertext werden vor der Entschlüsselung in konstanter Zeit geprüft.
- Beim Laden werden höchstens **5.000.000 Iterationen** akzeptiert.
- Ältere `ANON-AES256-1`-Tabellen bleiben mit einer Warnung ladbar und werden beim nächsten Speichern auf `ANON-AES256-2` gehoben.
- **Unbekannte Formate** (auch das frühere Browser-Format `ANON-WEBCRYPTO-AESGCM-1`, fremde oder beschädigte JSON-Dateien) führen zum Abbruch; die Datei wird **nie überschrieben**.
```powershell
# Mit eigenem Passwort (mind. 12 Zeichen, zweimalige verdeckte Abfrage):
.\anon.ps1 -Eingabe "C:\Faelle\Eingang" -Ausgabe "C:\Faelle\Ausgang" `
           -LokaleRegeln ".\anon-regeln.lokal.json" `
           -TabellenPfad "$env:LOCALAPPDATA\Anon\Tabellen\fall01.json" `
           -MitPasswort

# Explizit unverschlüsselte Ablage der Tabelle (nur wenn ausdrücklich gewünscht):
.\anon.ps1 -Eingabe "C:\Faelle\Eingang" -Ausgabe "C:\Faelle\Ausgang" `
           -LokaleRegeln ".\anon-regeln.lokal.json" `
           -Unverschluesselt
```

### Bestehende Zuordnungstabelle weiterverwenden (kein stiller Schutzverlust)
Wird eine verschlüsselte Tabelle (Passwort oder DPAPI) über `-Tabelle` geladen, merkt sich `anon.ps1` deren Schutzart und behält sie beim Speichern automatisch bei – selbst wenn `-MitPasswort` oder `-Dpapi` beim Folgelauf nicht erneut angegeben wurde:
```powershell
.\anon.ps1 -Eingabe "C:\Faelle\Nachlieferung.log" -Ausgabe "C:\Faelle\Ausgang2" `
           -LokaleRegeln ".\anon-regeln.lokal.json" `
           -Tabelle "$env:LOCALAPPDATA\Anon\Tabellen\fall01.json"
```

### IP-Modus (`-Netzerhaltend` / `-NichtNetzerhaltend`)
Beide sind Schalter und überschreiben `optionen.netzerhaltend` aus der Regeldatei: `-Netzerhaltend` erzeugt `NET-1.H17/24`, `-NichtNetzerhaltend` erzeugt `IP-PRIV-n` / `IP-PUB-n`. Beide zusammen werden abgelehnt.

### Trockenlauf (`-Probe`) und reiner Prüfmodus (`-Pruefen`)
```powershell
# Trockenlauf: Zeigt nur Anzahl Ersetzungen je Kategorie, schreibt keine Dateien
.\anon.ps1 -Eingabe "C:\Faelle\Eingang" -LokaleRegeln ".\anon-regeln.lokal.json" -Probe

# Reiner Prüfmodus auf einem bereits anonymisierten Ordner (Exit-Code 0 = SAUBER, Exit-Code 2 = Restfunde)
.\anon.ps1 -Eingabe "C:\Faelle\Ausgang\anonym" -LokaleRegeln ".\anon-regeln.lokal.json" -Pruefen
```

### Rückübersetzen einer KI-Antwort (`-Zurueck`)
```powershell
.\anon.ps1 -Zurueck -Eingabe "C:\Faelle\ki-antwort.txt" `
           -Ausgabe "C:\Faelle\ki-antwort-echt.txt" `
           -Tabelle "$env:LOCALAPPDATA\Anon\Tabellen\fall01.json"
```

---

## 5. Bedienung Variante B: Offline-Browser-App (`anonymisierer.html`)

1. Öffnen Sie `anonymisierer.html` per Doppelklick in Microsoft Edge oder Google Chrome.
2. **Reiter „2. Regeldatei (JSON)“:**
   - Laden Sie vor dem Lauf Ihre lokale `anon-regeln.lokal.json` von der Festplatte.
3. **Reiter „1. Anonymisieren & Prüfen“:**
   - Ziehen Sie Dateien, Ordner oder `.zip`/`.tar.gz`-Archive in das Drag-&-Drop-Feld.
   - Klicken Sie auf **„Anonymisieren & Prüfen“**.
   - Prüfen Sie oben rechts das Banner (**`SAUBER (0 Treffer)`** in Grün oder Restfunde in Rot) sowie darunter die Gegenüberstellung **Original vs. Anonymisiert**.
   - Laden Sie mit **„Anonymisiertes ZIP herunterladen“** das Freigabe-ZIP herunter (enthält ausschließlich `anonym/...` mit anonymisierten Dateinamen, **ohne** `bericht.json`).
4. **Reiter „3. Zuordnungstabelle (verschlüsselt)“:**
   - Geben Sie ein Passwort mit **mindestens 12 Zeichen** zweimal ein, um die Zuordnungstabelle verschlüsselt als `zuordnungstabelle.anontab` (Format `ANON-AES256-2`, PBKDF2-SHA256, auch in `anon.ps1` ladbar) herunterzuladen. Die Passwortfelder werden danach geleert.
   - Ältere Browser-Tabellen im Format `ANON-WEBCRYPTO-AESGCM-1` bleiben hier ladbar; speichern Sie sie einmal neu, um sie in `anon.ps1` nutzen zu können.
   - Zum Laden einer verschlüsselten Tabelle tragen Sie das Passwort **vor** dem Auswählen der Datei in das verdeckte Passwortfeld (`type="password"`) ein (es wird kein `prompt()`-Dialog verwendet, damit das Passwort nicht im Klartext auf dem Bildschirm erscheint).
5. **Reiter „4. Text (Datenschutz)“ (Nur Web / Browser):**
   > **Wichtiger Hinweis:** Text-Reiter nur Web, in `anon.ps1` nicht enthalten. Die Parität zwischen PowerShell und Web gilt für diesen Reiter nicht.
   - Dient der offlinebasierten Pseudonymisierung beliebiger Texte (E-Mails, Briefe, Notizen, Berichte, Tickets).
   - **Dreistufiges Modell:**
     - **ROT (automatisch aktiv):** E-Mail-Adressen, IBAN (Mod 97), Steuer-ID (Mod 11,10), KVNR (Mod 10), Telefon mit Vorwahl, Geburtsdatum mit Signalwort, IPv4/IPv6/URL, Personalausweis (Mod 10).
     - **GELB (Kandidaten zur Sichtprüfung):** Namen (Anrede, Listen, Grußzeilen), Straße+Nr, PLZ+Ort, Kfz-Kennzeichen, übrige Daten, RVNR (§ 147 SGB VI), LANR (KBV-Prüfziffer), BSNR (Signalwort), Fall-/Patientennummern, Station/Zimmer.
     - **Interaktive Farbvorschau:** Klick auf einen Treffer schaltet ihn aus bzw. an.
   - **Modi:** Strukturierte Token (`[NAME-1]`, `[IBAN-1]`) oder Schwärzung (`████████`).
   - **Wortwahl & Rechtsstatus:** Rückführbar über die Zuordnungstabelle. Ersetzt keine fachliche Sichtprüfung und keine Rechtsgrundlage. Ergebnis: *„Geprüft, n Treffer ersetzt, Sichtprüfung erforderlich“* (kein unkritisches `SAUBER`).
6. **Reiter „5. Rückübersetzen“:**
   - Fügen Sie die Antwort der KI ein und klicken Sie auf **„Jetzt rückübersetzen“**. Alles bleibt ausschließlich im RAM des Browsers.

---

## 6. Lokale Regeldatei (`anon-regeln.lokal.json`) auf der Admin-VM pflegen

`anon-regeln.lokal.json` enthält **nur Ergänzungen** zum Basisregelwerk `anon-regeln.json` und wird mit `-LokaleRegeln` (bzw. in `anonymisierer.html` über „anon-regeln.lokal.json laden“) übergeben. Beide Varianten führen die Dateien identisch zusammen: Begriffe werden ergänzt, Musterlisten werden **hinter** die Basismuster angehängt.

Übernommen werden:

| Bereich | Wirkung |
|---|---|
| `eigeneBegriffe.festeZuordnung`, `.firmenUndStandorte`, `.interneDomains` | eigene Begriffe, Rollen und Domains |
| `ausnahmen.exakteWoerter`, `.versionKontext`, `.musterRegex` | Werte, die im Klartext bleiben |
| `eigeneHostnamenMuster` | reguläre Ausdrücke für Ihr Namensschema (Treffer → `HOST-n`) |
| `hostnamenMuster`, `seriennummerMuster`, `benutzerMuster`, `geheimnisMuster`, `freitextMuster` | zusätzliche Erkennungsmuster |
| `tabellenSpalten` | zusätzliche Tabellen, deren Spalten ersetzt werden |
| `pruefung.erlaubtListe`, `.erlaubtMuster` | zusätzliche Ausnahmen im Prüfmodus |

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

### B. Eigenes Namensschema (`eigeneHostnamenMuster`)
Das Basisregelwerk erkennt nur generische Beispielpräfixe (`sw-`, `core-`, `dist-`, `acc-` mit mindestens einer Ziffer). Ihr echtes Namensschema gehört in die lokale Datei. Gruppe 1 (oder der ganze Treffer) wird zu `HOST-n`:
```json
"eigeneHostnamenMuster": [
  "(?i)(?<![A-Za-z0-9_-])(xy[0-9]-(?:sw|dist)[0-9]{2})(?![A-Za-z0-9_-])"
]
```
Einmal erkannte Hostnamen werden danach im gesamten Lauf ersetzt. Gesucht wird dabei mit den Grenzen `(?<![A-Za-z0-9_-])` und `(?![A-Za-z0-9_-])`, ein Name direkt an `_` oder `-` (z. B. `Uplink_XY1-SW01_P56`) wird also **nicht** ersetzt, aber vom Prüfmodus als `Rest-Bekannt` gemeldet.

### C. Tabellenspalten (`tabellenSpalten`)
Für Tabellen ohne Schlüsselwort pro Zeile (letzte Spalte von `show interface brief`, LLDP `PORT-DESC`/`SYS-NAME`, Cisco CDP `Device ID`) werden die Spaltengrenzen aus der Kopfzeile bestimmt. Eine Tabelle beginnt an einer Zeile, die alle Wörter aus `kopf` enthält, und endet an der nächsten Leerzeile. Werte nur aus Ziffern und Portnotation (`1/1/49`, `--`) bleiben stehen:
```json
"tabellenSpalten": [
  {
    "name": "Aruba AOS-CX show lldp neighbor-info",
    "kopf": ["LOCAL-PORT", "CHASSIS-ID", "PORT-ID", "PORT-DESC", "SYS-NAME"],
    "spalten": [
      { "name": "PORT-DESC", "kategorie": "TEXT" },
      { "name": "SYS-NAME", "kategorie": "HOST" }
    ]
  }
]
```

### D. Gerätenamen in Konfigurationszeilen (`hostnamenMuster`)
Alle mehrzeiligen Muster verwenden `(?=\r?$)` am Zeilenende, damit sie sowohl bei LF- als auch bei Windows-CRLF-Dateien in .NET und JavaScript identisch greifen:
```json
"hostnamenMuster": [
  "(?im)^([ \\t]*(?:hostname|sysname|switchname|prompt)[ \\t]+)([A-Za-z0-9._-]{2,64})([ \\t]*)(?=\\r?$)",
  "(?im)^([ \\t]*(?:System Name|Device ID)[ \\t]*:[ \\t]*)([A-Za-z0-9._-]{2,64})([ \\t]*)(?=\\r?$)",
  "(?i)(?<![A-Za-z0-9_-])((?:sw|core|dist|acc)-[A-Za-z0-9-]*[0-9][A-Za-z0-9-]*)(?![A-Za-z0-9_-])"
]
```

### E. Reihenfolge der Engine (identisch in `anon.ps1` und `anonymisierer.html`)
0. Tabellenspalten (`tabellenSpalten`) über Spaltenpositionen der Kopfzeile
1. Geheimnisse entfernen (`*****`)
2. Ausnahmen schützen (Versionen wie `10.13.1020`, Portnamen, Masken, Uhrzeiten, `ausnahmen.musterRegex`)
3. Freitext-Felder (`description`, `location`, Banner, ...) → `TEXT-n`, `ORT-n`, `KONTAKT-n`, `BANNER-n`
4. Eigene Begriffe (`festeZuordnung`, `firmenUndStandorte`)
5. Seriennummern → `SERIAL-n`
6. Benutzer → `USER-n`
7. E-Mail und URL → `MAIL-n`, `URL-n`
8. MAC-Adressen (alle Schreibweisen) → `MAC-n`
9. IPv6, danach IPv4 → `IP6-…`, `NET-n.Hm`
10. Hostnamen (Muster, CLI-Prompt, im Lauf bekannte Hosts), FQDNs und interne Domains → `HOST-n`, `DOMAIN-n`
11. Schutz-Marker linear auflösen

Nicht ersetzt werden u. a. Versionen (`10.13.1020`), Portnamen, VLAN-IDs, Produktnamen (`ausnahmen.exakteWoerter`), Subnetz-/Wildcard-Masken, Uhrzeiten und das Wort `hash`.

---

## 7. Sicherheitskonzept & Grenzen des Werkzeugs

1. **Die Zuordnungstabelle ist so vertraulich wie das Original:**
   Wer die Zuordnungstabelle besitzt, kann alle Platzhalter wieder in echte IP-Adressen, Hostnamen und Seriennummern umwandeln (ausgenommen Geheimnisse, da diese durch `*****` gelöscht wurden). Bewahren Sie die Tabelle daher immer getrennt und verschlüsselt auf.
2. **Regex-Timeouts (Variante A vs. Variante B):**
   In Variante A (`anon.ps1` / .NET) sind sämtliche regulären Ausdrücke mit einem harten `MatchTimeout` von **5 Sekunden** gegen katastrophales Backtracking (ReDoS) bei selbstgebauten Regeln abgesichert. In Variante B (`anonymisierer.html`) unterstützt die JavaScript-Engine (`RegExp`) des Browsers nativ **kein** Regex-Timeout; achten Sie beim Erweitern eigener Muster in `anon-regeln.lokal.json` daher auf eindeutige Begrenzungen ohne geschachtelte Quantifizierer.
3. **Netzwerk-Topologie und Struktur bleiben erkennbar:**
   Durch konsistente Platzhalter (`NET-1.H1/24`, `CORE-A`, `MAC-1`) bleibt die logische Struktur für die Fehlersuche erhalten.
4. **Freitext immer selbst sichten:**
   Unstrukturierter Freitext (z. B. ungewöhnliche Log-Meldungen, Skript-Kommentare ohne Schlüsselwort) kann Begriffe enthalten, die keiner bekannten Regel entsprechen. Eine manuelle Sichtprüfung vor der Weitergabe ist daher unverzichtbar.

---

## 8. Tests ausführen

### Prüfbefehl für die Admin-VM (Windows PowerShell 5.1)
Prüft, dass die C#-Engine unter PS 5.1 kompiliert, und zeigt die .NET-Version (für PBKDF2-SHA256 ist 4.7.2 nötig, Release-Wert ≥ 461808):
```powershell
cd C:\Tools\anonymisierer
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$PSVersionTable.PSVersion.ToString(); (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\anon.ps1 -Pruefen -Eingabe .\tests\erwartet
```
Erwartet: Version `5.1.x`, eine Release-Nummer und `Prüfergebnis: SAUBER (0 Treffer)` mit Exit-Code `0`. Ein Kompilierfehler der Engine erscheint als `Add-Type`-Fehler.

Danach die vollständige Testsuite (Exit-Code `0` = alles grün):
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
```

### Regeln für Testdaten und Regex
- `tests\erwartet\` ist der committete Sollstand. `run-tests.js` vergleicht nur; neu erzeugen bei gewollter Änderung: `node tests/run-tests.js --aktualisieren`.
- In `anon-regeln.json` sind `\w`, `\d` und `\b` verboten (in .NET Unicode, in JavaScript nur ASCII). Stattdessen `[0-9]`, `[A-Za-z0-9_]`, `(?<![A-Za-z0-9_])` / `(?![A-Za-z0-9_])`. Ersetzungstexte dürfen nur `$1` bis `$9` verwenden.
- Alle `.ps1`-Dateien sind UTF-8 **mit BOM** gespeichert (sonst liest PS 5.1 sie als ANSI) und enthalten keine Gedankenstriche.

Der Ordner `tests\` enthält **61 synthetische Test- und Grenzfälle** (`tests\faelle.json`), die automatisch sowohl als LF- als auch als CRLF-Variante geprüft werden, realistische Beispieldateien (`tests\beispiele\`), erwartete Referenzausgaben (`tests\erwartet\`) sowie dedizierte Tests für alle Sicherheits-, Sammler- und Randfälle.

- **PowerShell-Testsuite starten:**
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
  ```
- **Node.js-Testsuite starten (für `anonymisierer.html` & Paritätstest):**
  ```bash
  node tests/run-tests.js
  ```

---

## 9. Eingebettete Komponenten & Lizenzen

- **Lizenz des Projekts (`anon.ps1`, `anonymisierer.html`, `anon-regeln.json`, `switch-sammler.ps1`):** noch offen.
- **ZIP- und TAR/GZIP-Verarbeitung in `anonymisierer.html`:** Direkt eingebetteter Minimal-Codec auf Basis der standardisierten Browser-APIs (`DecompressionStream`, `DataView`, `Uint8Array`, `WebCrypto API`) ohne externe Fremdbibliotheken.

### Inspiriert von
Konzepte (kein Code) wurden übernommen aus:
- [netconan](https://github.com/intentionet/netconan) (intentionet, Apache-2.0): Kategorien von Geheimnismustern, Maskenerkennung, reservierte Wörter.
- [Presidio](https://github.com/data-privacy-stack/presidio) (ursprünglich Microsoft, MIT): Erkenner mit Grundwert, Prüfziffer-Validierung, Kontextwörter und getrennte Operatoren pro Kategorie für den Reiter „Text (Datenschutz)“.

Details: [`docs/lese-auftrag-netconan-presidio.md`](./docs/lese-auftrag-netconan-presidio.md)
