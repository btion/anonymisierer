# Netzwerk-Anonymisierer (`anon.ps1` & `anonymisierer.html`)

Offline-Werkzeug zum konsistenten Anonymisieren von Netzwerk-Logs, Show-Techs, Konfigurationsdateien und JSON-Dumps (Aruba AOS-CX/AOS-S, HPE Comware, Dell Enterprise SONiC, Dell OS10, MikroTik RouterOS v6/v7, Cisco IOS/NX-OS, FortiGate, Sophos XG/SFOS, Linux-Syslog, Windows-Eventlogs), bevor diese an eine KI oder externe Experten übergeben werden.

Beide Anonymisierer-Varianten verwenden exakt dasselbe Regelschema ([`regeln/anon-regeln.json`](./regeln/anon-regeln.json)) und liefern identische Ausgaben (sowohl bei LF- als auch bei CRLF-Dateien):
1. **Variante A – PowerShell-CLI ([`powershell/anon.ps1`](./powershell/anon.ps1)):** Läuft auf Windows (Admin-VM) unter Windows PowerShell 5.1 (sowie PowerShell 7+) ohne Python, ohne externe Module und ohne Internetverbindung. Dank eingebetteter C#-Engine (mit 5-Sekunden-Regex-Timeout je Ausdruck) werden auch große Dateien (bis 50 MB) und Show-Tech-Archive mit tausenden Dateien schnell verarbeitet.
2. **Variante B – Eigenständige Browser-App ([`web/anonymisierer.html`](./web/anonymisierer.html)):** Eine einzige HTML-Datei (HTML, CSS, JS inkl. eingebettetem ZIP/TAR.GZ-Codec), die per Doppelklick in Edge oder Chrome komplett offline im Arbeitsspeicher (RAM) läuft und durch eine strikte `Content-Security-Policy` (`default-src 'none'; connect-src 'none'`) jeglichen Netzwerkverkehr unterbindet.

Zusätzlich gibt es den **Text-Anonymisierer** ([`web/text/text-anonymisierer.html`](./web/text/text-anonymisierer.html)) für Freitext (E-Mails, Briefe, Notizen), eine eigene Offline-Seite mit demselben Tabellenformat (siehe Abschnitt 5b).

> **English summary:** see [README.en.md](./README.en.md).

---

## Inhaltsverzeichnis
1. [Installation & Bereitstellung](#1-installation--bereitstellung)
2. [Empfohlener Arbeitsablauf (6 Schritte)](#2-empfohlener-arbeitsablauf-6-schritte)
3. [Sammler: eigenes Projekt](#3-sammler-eigenes-projekt)
4. [Bedienung Variante A: PowerShell (`anon.ps1`)](#4-bedienung-variante-a-powershell-anonps1)
5. [Bedienung Variante B: Offline-Browser-App (`anonymisierer.html`)](#5-bedienung-variante-b-offline-browser-app-anonymisiererhtml)
   - [5b. Text-Anonymisierer (`text-anonymisierer.html`)](#5b-text-anonymisierer-text-anonymisiererhtml)
6. [Lokale Regeldatei (`anon-regeln.lokal.json`) auf der Admin-VM pflegen](#6-lokale-regeldatei-anon-regelnlokaljson-auf-der-admin-vm-pflegen)
7. [Sicherheitskonzept & Grenzen des Werkzeugs](#7-sicherheitskonzept--grenzen-des-werkzeugs)
8. [Tests ausführen](#8-tests-ausführen)
9. [Eingebettete Komponenten & Lizenzen](#9-eingebettete-komponenten--lizenzen)
10. [Repository-Struktur](#10-repository-struktur)

---

## 1. Installation & Bereitstellung

Kopieren Sie den Projektordner auf Ihre Admin-VM (z. B. nach `C:\Tools\anonymisierer\`). Benötigt werden:
- `powershell\anon.ps1`
- `regeln\anon-regeln.json` (Basisregelwerk ohne echte Infrastrukturdaten) und `regeln\strukturvorlage.json` (Schlüsselwortliste für `-Strukturvorlage` und **Lern-Stoppliste**; `anon.ps1` bricht ohne diese Datei ab)
- `web\anonymisierer.html` und `web\text\text-anonymisierer.html` (eigenständige Offline-Seiten)
- `tests\` (für den Prüfbefehl in Abschnitt 8)

Alternativ können `anon.ps1` und `anon-regeln.json` flach im selben Ordner liegen; `anon.ps1` sucht die Regeldatei zuerst neben sich, dann unter `..\regeln\`.

Es wird keine Installation, kein Internetzugang und kein zusätzliches PowerShell-Modul benötigt.

> **Wichtiger Hinweis zur Trennung von Vorlage und echten Namen (`anon-regeln.lokal.json`):**
> Die mitgelieferte Datei `anon-regeln.json` ist das Basisregelwerk und enthält ausschließlich synthetische Beispielwerte. Legen Sie auf Ihrer Admin-VM daneben eine **`anon-regeln.lokal.json`** an, die **nur Ihre Ergänzungen** enthält (echte Gerätenamen, Firmennamen, interne Domains, eigene Hostnamen-Muster), und übergeben Sie sie mit **`-LokaleRegeln`**. Die Basisregeln bleiben dabei aktiv. Geben Sie `anon-regeln.lokal.json` niemals weiter und laden Sie sie nirgendwo hoch!

---

## 2. Empfohlener Arbeitsablauf (6 Schritte)

```
[1. Sammeln] -> [2. Anonymisieren] -> [3. Prüfen (-Pruefen)] -> [4. Sichtprüfung] -> [5. Weitergabe] -> [6. Rückübersetzen]
```

1. **Sammeln:**
   Legen Sie die Switch-Ausgaben (z. B. aus dem Sammler, siehe Abschnitt 3) oder bestehende Show-Tech-Ordner / `.zip`/`.tar.gz`-Archive in einem lokalen Eingabeordner ab.
2. **Anonymisieren:**
   Starten Sie `anon.ps1` mit Ihrer lokalen Regeldatei `-LokaleRegeln .\anon-regeln.lokal.json` (oder laden Sie die lokale Regeldatei in `anonymisierer.html` unter „Eigene Begriffe“). `-Regeln` bleibt für das Basisregelwerk (`anon-regeln.json`, Standard im Skriptordner).
   - Alle Dateien werden in zwei Durchläufen verarbeitet: Ein Hostname, der erst in Datei 3 erkannt wird, wird so auch in Datei 1 ersetzt.
   - Dateien mit UTF-8-BOM sowie UTF-16 LE/BE BOM (z. B. Windows-Eventlogs) werden automatisch anhand des BOM erkannt und immer als UTF-8 ohne BOM ausgegeben.
   - Auch alle Datei- und Ordnernamen im Ausgabepfad werden durch die Engine anonymisiert (z. B. `show-tech-dc1-sw-core01.txt` -> `show-tech-CORE-A.txt`).
   - Geheimnisse (Passwörter, Hashes, `ciphertext`, HPE Comware `password/key cipher|simple|hash`, MikroTik `private-key=`/`public-key=`, SNMP-Communities, PSKs, PEM-Blöcke) werden unwiderruflich durch `*****` entfernt.
   - Infrastrukturdaten (IPs mit netzerhaltendem Format `NET-1.H17/24`, MACs als `MAC-1`, Hostnamen als `HOST-1` bzw. feste Rollen wie `CORE-A` / `TOR-A`, VLAN-Namen und Beschreibungen als `TEXT-1`) werden über alle Dateien hinweg konsistent ersetzt.
   - Die Zuordnungstabelle wird **außerhalb** des Ausgabeordners unter `%LOCALAPPDATA%\Anon\Tabellen\` abgelegt (geschützt per Windows-ACL auf Ihren Benutzer sowie standardmäßig unter Windows mit DPAPI oder per `-MitPasswort` mit `ANON-AES256-2` verschlüsselt).
   - Archive werden **nicht** im Ausgabeordner entpackt, sondern unter `%LOCALAPPDATA%\Anon\arbeit\<zufall>\` (ACL nur Ihr Benutzer). Der Ordner wird nach jedem Lauf gelöscht, auch bei Fehler oder Abbruch (Strg+C). Reste eines hart beendeten Laufs werden beim nächsten Start entfernt.
   - Konsole und Fehlermeldungen enthalten **keine echten Werte**: Prüftreffer nur mit Kategorie, Datei und Zeile; Fehler nur mit laufender Nummer der Datei, Schritt und Fehlerart.
3. **Prüfen (`-Pruefen`):**
   Nach jedem Lauf sucht der Prüfmodus automatisch in allen Ausgabedateien **und Dateipfaden** nach eventuell verbliebenen IPv4/IPv6-Adressen, MAC-Adressen (alle Schreibweisen), E-Mail-Adressen, Sperrbegriffen, nicht entfernten Geheimnissen (alle `geheimnisMuster`), Hashes, langen Hex/Base64-Blobs, Hostnamen, Seriennummern, Benutzern, nicht ersetzten Freitext-Feldern und Tabellenspalten. Zusätzlich sucht er nach allen Originalwerten, die im Lauf erkannt wurden (Hosts, Seriennummern, Benutzer, Mail, Firmen), auch dort, wo sie direkt an `-` grenzen (z. B. `XY1-SW01-alt`).
   - Nur wenn **0 Treffer** vorliegen, lautet das Ergebnis **„Keine Restfunde nach aktivem Regelwerk“** (Konsole und `bericht.json`: `KEINE_RESTFUNDE`, Exit-Code `0`).
   - **Bedeutung:** „Keine Restfunde nach aktivem Regelwerk“ heißt nur, dass keine der aktiven Regeln und Prüfungen noch etwas findet. Es ist **keine Garantie**, dass die Daten frei von Echtwerten sind: Formate, für die es keine Regel gibt (ungewöhnlicher Freitext, neue Gerätetypen), erkennt der Prüfmodus nicht. Deshalb bleibt die Sichtprüfung Pflicht. Früher hieß das Ergebnis `SAUBER`; die Bezeichnung wurde geändert, weil sie mehr versprach, als die Prüfung leisten kann.
   - Werden Restfunde entdeckt (`RESTFUNDE_VORHANDEN`), beendet sich `anon.ps1` auch im Hauptlauf mit **Exit-Code `2`** und dem Hinweis **„NICHT weitergeben“**. Ergänzen Sie in diesem Fall das fehlende Muster in Ihrer `anon-regeln.lokal.json` und starten Sie den Lauf erneut.
4. **Sichtprüfung (Pflichtschritt vor jeder Weitergabe!):**
   Prüfen Sie die anonymisierten Dateien in `<Ausgabe>\anonym\` (bzw. in der Side-by-Side-Vorschau von `anonymisierer.html`) stichprobenartig mit eigenen Augen – insbesondere ungewöhnliche Freitext-Kommentare, Debug-Ausgaben oder mehrzeilige Notizen.
5. **Weitergabe:**
   Geben Sie **ausschließlich** den Unterordner `<Ausgabe>\anonym\` (bzw. das heruntergeladene `anonym-ausgabe.zip`, das keine `bericht.json` enthält) an die KI oder den externen Experten weiter – niemals den Quellordner und niemals die Zuordnungstabelle!
6. **Rückübersetzen (`-Zurueck`):**
   Wenn die KI oder der Experte eine Diagnose oder Konfigurationsänderung mit Platzhaltern liefert (z. B. `Prüfen Sie auf CORE-A das VLAN auf Port Ethernet1/1/10 zu TOR-A mit IP NET-1.H2/24`), übersetzen Sie den Text lokal mit `-Zurueck` (bzw. im Reiter *„4. Rückübersetzen“* in `anonymisierer.html`) mithilfe Ihrer gespeicherten Zuordnungstabelle wieder in die echten Infrastrukturwerte zurück.

---

## 3. Sammler: eigenes Projekt

Der Read-Only Switch-Sammler (`switch-sammler.ps1`, `sammler-befehle.json`) wird als eigenes Repository weiterentwickelt und ist nicht mehr Teil dieses Projekts. Seine Ausgaben (Ordner oder `.zip`/`.tar.gz`) werden hier wie jede andere Eingabe anonymisiert.

---

## 4. Bedienung Variante A: PowerShell (`anon.ps1`)

### Standardlauf (Ordner, Einzeldateien oder `.zip` / `.tar.gz`)
Unter Windows schützt `anon.ps1` neue Zuordnungstabellen standardmäßig mit **Windows DPAPI (`CurrentUser`)** plus NTFS-ACL:
```powershell
cd C:\Tools\anonymisierer\powershell

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

### Strukturvorlage (`-Strukturvorlage`) für die Regelentwicklung
Erzeugt aus Eingabedateien Kopien, die nur die **Form** der Daten zeigen: Großbuchstabe → `A`, Kleinbuchstabe → `a`, Ziffer → `9`, Sonderzeichen bleiben. Bekannte CLI-Schlüsselwörter und Tabellenköpfe aus der **festen Liste** `regeln/strukturvorlage.json` bleiben stehen (die Liste wird nie aus Eingabedateien gelernt), Freitextfelder (description, name, location, contact, banner, comment, Beschreibungsspalten) werden `<FREITEXT>`, Geheimnisse `*****`. So lassen sich Muster für reale Formate entwickeln, ohne Echtdaten weiterzugeben. **Vor Weitergabe sichten!**
```powershell
.\anon.ps1 -Strukturvorlage -Eingabe "C:\Faelle\Eingang\show-tech.txt" -Ausgabe "C:\Faelle\Struktur"
```
Die Ausgabedateien heißen `strukturvorlage-001.txt` usw. (Originalnamen können Werte enthalten). Ohne `-Ausgabe`: `%LOCALAPPDATA%\Anon\struktur\<Zeitstempel>\`. In `anonymisierer.html`: Karte „4. Strukturvorlage“ im ersten Reiter (Download als `strukturvorlage.zip`).

### IP-Modus (`-Netzerhaltend` / `-NichtNetzerhaltend`)
Beide sind Schalter und überschreiben `optionen.netzerhaltend` aus der Regeldatei: `-Netzerhaltend` erzeugt `NET-1.H17/24`, `-NichtNetzerhaltend` erzeugt `IP-PRIV-n` / `IP-PUB-n`. Beide zusammen werden abgelehnt.

### Trockenlauf (`-Probe`) und reiner Prüfmodus (`-Pruefen`)
```powershell
# Trockenlauf: Zeigt nur Anzahl Ersetzungen je Kategorie, schreibt keine Dateien
.\anon.ps1 -Eingabe "C:\Faelle\Eingang" -LokaleRegeln ".\anon-regeln.lokal.json" -Probe

# Reiner Prüfmodus auf einem bereits anonymisierten Ordner (Exit-Code 0 = KEINE_RESTFUNDE, Exit-Code 2 = RESTFUNDE_VORHANDEN)
.\anon.ps1 -Eingabe "C:\Faelle\Ausgang\anonym" -LokaleRegeln ".\anon-regeln.lokal.json" -Pruefen
```

### Rückübersetzen einer KI-Antwort (`-Zurueck`)
Der Klartext wird nie auf der Konsole ausgegeben. Ohne `-Ausgabe` landet er in `%LOCALAPPDATA%\Anon\klartext\rueck-<Zeitstempel>-001.txt` (ACL nur Ihr Benutzer). Ein Ziel unterhalb eines Ordners `anonym\` oder in einem Ausgabeordner eines Laufs (erkennbar an `anonym\` und `bericht.json`) wird abgelehnt.
```powershell
.\anon.ps1 -Zurueck -Eingabe "C:\Faelle\ki-antwort.txt" `
           -Ausgabe "C:\Klartext\ki-antwort-echt.txt" `
           -Tabelle "$env:LOCALAPPDATA\Anon\Tabellen\fall01.json"
```

---

## 5. Bedienung Variante B: Offline-Browser-App (`anonymisierer.html`)

Öffnen Sie `web\anonymisierer.html` per Doppelklick in Microsoft Edge oder Google Chrome. Oben gibt es nur drei Bereiche: **Anonymisieren · Rückübersetzen · Einstellungen**. Die Statuszeile zeigt jederzeit den Stand: „Noch nicht geprüft“ (neutral), „Verarbeitung läuft (Datei x von y)“, „N Fundgruppen brauchen eine Entscheidung“, „Ergebnis veraltet – erneut verarbeiten“, „Unvollständig – N Dateien nicht verarbeitet“ oder „Keine Restfunde nach aktivem Regelwerk – Vorschau prüfen“. Meldungen erscheinen an der betroffenen Stelle (kein `alert()`), Statusmeldungen werden Screenreadern angesagt.

„Anonymisieren“ ist ein Ablauf in vier Schritten, die frei anspringbar sind:

1. **Dateien auswählen:** Dateien, Ordner oder `.zip`/`.tar.gz` hineinziehen. Die Dateiliste zeigt je Datei den **verdeckten** Namen (vor dem Verarbeiten „Datei n“, danach den anonymisierten Namen; Originalnamen nur über „Originale anzeigen“, beim Verlassen von Schritt 1 wieder verdeckt), Typ und Status (bereit, verarbeitet, übersprungen, nicht unterstützt, Fehler), lässt Dateien entfernen und durchsuchen und fasst zusammen („24 geladen, 22 verarbeitet, 2 nicht unterstützt“). Nicht verarbeitete Dateien bleiben sichtbar. Wählen Sie **Neue Zuordnung** oder **Vorhandene Zuordnung laden** (Passwort zuerst eingeben, dann die Datei wählen; kein `prompt()`).
2. **Verarbeiten:** Zusammenfassung der Dateien und der Einstellungen („Standardeinstellungen aktiv“ oder sichtbare Abweichungen, z. B. „Benutzernamen werden nicht ersetzt“), dann **„Anonymisieren und prüfen“**. Der Trockenlauf liegt unter „Erweitert“; er gibt nichts frei.
3. **Ergebnis prüfen:** Jede Fundkarte nennt die Art in Klartext („Möglicher Benutzername“), Anzahl und Dateien, zeigt eine Kontextzeile mit markiertem Wert und die Fundorte. Ein Klick auf einen Fundort öffnet die Datei in der Vorschau, springt zur Zeile und markiert den Wert, auch hinter den ersten 200 KB (es wird ein Ausschnitt um die Stelle geladen). Entscheidungen:
   - **Alle Vorkommen ersetzen:** Der Wert wird zur eigenen Ersetzung mit Platzhalter; Geheimnisse werden stattdessen zu `*****` (nie in der Zuordnung).
   - **Unverändert lassen:** Der Wert bleibt sichtbar („Dieser Wert bleibt in den weiterzugebenden Dateien sichtbar.“) und gilt nur für seine Kategorie (`ausnahmen.freigegeben`), nicht als allgemeine Ausnahme.
   - **Sicher erkannte Geheimnisse** (Treffer einer `geheimnisMuster`-Regel, Zugangsdaten mit eindeutigem Schlüsselwort wie `password`/`secret`/`api-key`/`authorization`, Passwort-Hashes, teilweise maskierte Werte): nur „Alle Vorkommen ersetzen (*****)“ oder „Datei aus dem Auftrag entfernen“; Freigabe gesperrt.
   - **Verdachtsfunde** (langer Hex-/Base64-Wert wie Build-ID oder Prüfsumme, `token`/`pwd`, alle Heuristiken der Nachprüfung): „Unverändert lassen“ nach der Bestätigung „Ich habe geprüft: kein Geheimnis“ (Freigabe in Kategorie `Verdacht`) oder „Als Geheimnis maskieren (*****)“.
   - Jede Fundgruppe hat mindestens zwei Aktionen, nie eine Sackgasse; wo sonst nur eine bliebe (eigene Begriffe, interne Domains), kommt „Datei aus dem Auftrag entfernen“ hinzu.
   - Umfang: **nur für diesen Auftrag** (Standard; endet mit „Dateien und Ergebnisse zurücksetzen“) oder **als dauerhafte Regel übernehmen** (landet in den Einstellungen und wird mit `anon-regeln.lokal.json` gespeichert; bis dahin warnen ein Hinweis und das Schließen des Fensters).
   - Jede Entscheidung ist rückgängig zu machen; „Nächster offener Fund“ springt weiter. Danach **„Entscheidungen anwenden und neu verarbeiten“**.
   - Die Vorschau markiert ersetzte Stellen, zeigt Zeilennummern und bietet „Nur geänderte Zeilen“, „Nächste Änderung“, Suche, synchrones Scrollen und **„Diese Datei herunterladen“**. Die Originalspalte ist standardmäßig ausgeblendet (Bildschirmfreigabe). Die Vorschau steht neben dem breiteren Fundbereich oder, umschaltbar, darunter.
   - Reiter **Ersetzungen** neben „Funde“: Kategorie, Platzhalter, Original (standardmäßig verdeckt, „Originale anzeigen“), Anzahl in der Ausgabe, Suche; „Zur Stelle“ springt in der Vorschau zum ersten Vorkommen. Umbenennen, Entfernen und Hinzufügen direkt hier (bisher unter Einstellungen › Erweitert).
   - „Getroffene Entscheidungen“ und „Alle Einzelfunde“ sind eingeklappt, solange sie leer sind.
4. **Herunterladen:** **Anonymisierte Dateien – zur Weitergabe**: Ergebnis-ZIP (nur `anonym/...`, ohne Bericht und Zuordnung) und Liste aller Dateien mit Einzel-Download (anonymisierter Name, ursprünglicher Dateityp); bei nur einer Datei ist der Einzel-Download der Hauptknopf. Gleiche Sperrregeln für ZIP und Einzeldateien; ein unvollständiger Lauf (nicht verarbeitete Dateien) sperrt den Download, bis diese Dateien entfernt und neu verarbeitet sind. Außerdem **Verschlüsselte Zuordnungstabelle – vertraulich aufbewahren** (Passwort mit mindestens 12 Zeichen, Format `ANON-AES256-2`, auch in `anon.ps1` ladbar; Hinweis, wenn sich die Zuordnung seit dem letzten Speichern geändert hat) und **Technischer Bericht (ohne Werte)** mit `bewusstFreigegeben`. Ein gesperrter Download nennt immer den Grund und den nächsten Schritt. Freigegeben wird nur nach einem vollständigen Lauf mit „Keine Restfunde nach aktivem Regelwerk“; jede Änderung an Dateien, Einstellungen, Regeln oder Zuordnung macht das Ergebnis veraltet.

**Rückübersetzen:** Antwort der KI einfügen; Platzhalter werden lokal wieder zu Originalwerten, z. B. `HOST-1` wieder zum ursprünglichen Gerätenamen.

**Einstellungen:** Kategorien und Optionen, **Eigene Ersetzungen** (`festeZuordnung`), **Firmen und Standorte**, **Interne Domains**, **Nicht anonymisieren** (`ausnahmen.exakteWoerter`) und **Bewusst freigegebene Werte**; unter „Erweitert“ Regeldatei, eigene Gerätenamen-Muster, Strukturvorlage, ein Verweis auf die Ersetzungen in Schritt 3 und Angaben zur Verschlüsselung. Ältere Browser-Tabellen (`ANON-WEBCRYPTO-AESGCM-1`) bleiben ladbar; einmal neu speichern, um sie in `anon.ps1` zu nutzen.

### 5b. Text-Anonymisierer (`text-anonymisierer.html`)

Eigene Offline-Seite `web\text\text-anonymisierer.html` (gleiche CSP, kein Netz, nur RAM). Sie nutzt denselben Kern (`core\tabelle\`) wie `anonymisierer.html`: Die Zuordnungstabelle wird als `ANON-AES256-2` gespeichert und ist in beiden Seiten und in `anon.ps1` ladbar; Text-Platzhalter wie `[NAME-1]` werden überall zurückübersetzt.

> **Wichtiger Hinweis:** Text-Reiter nur Web, in `anon.ps1` nicht enthalten. Die Parität zwischen PowerShell und Web gilt für den Text-Anonymisierer nicht.
- Dient der offlinebasierten Pseudonymisierung beliebiger Texte (E-Mails, Briefe, Notizen, Berichte, Tickets).
- **Dreistufiges Modell:**
  - **ROT (automatisch aktiv):** E-Mail-Adressen, IBAN (Mod 97), Steuer-ID (Mod 11,10), KVNR (Mod 10), Telefon mit Vorwahl, Geburtsdatum mit Signalwort, IPv4/IPv6/URL, Personalausweis (Mod 10).
  - **GELB (Kandidaten zur Sichtprüfung):** Namen (Anrede, Listen, Grußzeilen), Straße+Nr, PLZ+Ort, Kfz-Kennzeichen, übrige Daten, RVNR (§ 147 SGB VI), LANR (KBV-Prüfziffer), BSNR (Signalwort), Fall-/Patientennummern, Station/Zimmer.
  - **Interaktive Farbvorschau:** Klick auf einen Treffer schaltet ihn aus bzw. an.
- **Mechanismus pro Kategorie** (Auswahl auf der Seite, „Vorgabe“ folgt dem Ersetzungs-Modus Token bzw. Schwärzung):
  - `Platzhalter`: `[NAME-1]`, `[IBAN-1]`, rückführbar über die Zuordnungstabelle; die Nummerierung läuft über mehrere Texte weiter.
  - `Entfernen`: Schwärzung `████████`, nicht rückführbar.
  - `Generalisieren`: vergröberter Wert, nicht rückführbar. Regeln: Datum/Geburtsdatum → Jahr, PLZ + Ort → `12xxx`, Straße + Nr. → Straße, Telefon → Vorwahl `030 …`, E-Mail → `…@domain`, IPv4 → `192.0.2.x`. Kategorien ohne Regel erhalten einen Platzhalter.
- **Wortwahl & Rechtsstatus:** Rückführbar über die Zuordnungstabelle. Ersetzt keine fachliche Sichtprüfung und keine Rechtsgrundlage. Ergebnis: *„Geprüft, n Treffer ersetzt, Sichtprüfung erforderlich“* (kein Freigabe-Urteil wie im Netzwerk-Anonymisierer).
- **Zuordnungstabelle & Rückübersetzen** befinden sich unten auf derselben Seite (Passwortfelder werden nach dem Export und Laden geleert).

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
| `ausnahmen.freigegeben` | bewusst unverändert gelassene Werte, nur für ihre Kategorie: `[{ "kategorie": "Benutzer", "wert": "…" }]`. Kategorien: Benutzer, Hostname, Seriennummer, Domaene, IPv4, IPv6, MAC, EMail, URL, Freitext, Tabellenfeld, Verdacht (Verdachtsfunde: langer Hex-/Base64-Wert, `token`/`pwd`, Heuristiken der Nachprüfung), SID. Sicher erkannte Geheimnisse, Sperrbegriffe und interne Domains sind nicht freigebbar. Der Prüfmodus zählt solche Funde als „bewusst freigegeben (N)“ (Konsole, `bericht.json` → `bewusstFreigegeben`, ohne Werte) |

### A. Eigene Begriffe, Rollen & Domains (`eigeneBegriffe`)
Begriffe in `festeZuordnung` und `firmenUndStandorte` werden automatisch mit Namensgrenzen `(?<![A-Za-z0-9-])...(?![A-Za-z0-9-])` gesucht, sodass z. B. `"dc1-tor-01"` niemals versehentlich den Anfang von `"dc1-tor-010"` zu `"TOR-A0"` verfälscht:
```json
"eigeneBegriffe": {
  "festeZuordnung": {
    "dc1-sw-core01": "CORE-A",
    "dc2-sw-core02": "CORE-B",
    "dc1-tor-01": "TOR-A"
  },
  "firmenUndStandorte": [
    "Musterfirma GmbH",
    "Rechenzentrum-Nord",
    "Max Mustermann"
  ],
  "interneDomains": [
    "intern.example.invalid",
    "ad.firma.lan"
  ]
}
```

### B. Eigenes Namensschema (`eigeneHostnamenMuster`)
Das Basisregelwerk erkennt nur generische Beispielpräfixe (`sw-`, `core-`, `dist-`, `acc-` mit mindestens einer Ziffer). Ihr echtes Namensschema gehört in die lokale Datei. Gruppe 1 (oder der ganze Treffer) wird zu `HOST-n`:
```json
"eigeneHostnamenMuster": [
  "(?i)(?<![A-Za-z0-9-])(xy[0-9]-(?:sw|dist)[0-9]{2})(?![A-Za-z0-9-])"
]
```
Einmal erkannte Hostnamen werden danach im gesamten Lauf ersetzt. Gesucht wird mit den Grenzen `(?<![A-Za-z0-9-])` und `(?![A-Za-z0-9-])`: `_` gilt als Trennzeichen (Hostnamen enthalten nach RFC 1123 keinen Unterstrich, in Beschreibungen ist er der übliche Trenner), aus `Uplink_XY1-SW01_P56` wird also `Uplink_HOST-1_P56`. Ein Name direkt an `-` (z. B. `XY1-SW01-alt`) wird nicht ersetzt, aber vom Prüfmodus als `Rest-Bekannt` gemeldet.

### C. Tabellenspalten (`tabellenSpalten`)
Für Tabellen ohne Schlüsselwort pro Zeile (letzte Spalte von `show interface brief`, auch ohne Spalten `Mode`/`Enabled`, LLDP `PORT-DESC`/`SYS-NAME`, Cisco CDP `Device ID`) werden die Spaltengrenzen aus der Kopfzeile bestimmt; enthält die Kopfzeile Tabulatoren, gilt die Feldnummer statt der Zeichenposition. Eine Tabelle beginnt an einer Zeile, die alle Wörter aus `kopf` enthält, und endet an der nächsten Leerzeile. Werte nur aus Ziffern und Portnotation (`1/1/49`, `--`) bleiben stehen:
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
  "(?i)(?<![A-Za-z0-9-])((?:sw|core|dist|acc)-[A-Za-z0-9-]*[0-9][A-Za-z0-9-]*)(?![A-Za-z0-9-])"
]
```

### Lernregeln, JSON, Dateinamen und Platzhalter (Paket A)
- **Geheimnisse zuerst:** Geheimnisse werden auf dem Original entfernt, bevor ein Wert als Freitext oder Tabellenspalte in die Zuordnungstabelle gelangt; dort steht nie ein Geheimnis.
- **Generische Zugangsdaten:** `password`, `passwd`, `passwort`, `kennwort`, `pwd`, `secret`, `api_key`, `token` mit `:`, `=` oder Leerzeichen sowie `Authorization: Basic/Bearer` werden entfernt. Der Prüfmodus meldet solche Schlüsselwörter mit nicht maskiertem Wert als `Verdacht-Zugangsdaten`.
- **JSON:** Zeichenketten werden escape-bewusst gelesen (`\"` im Wert), `\uXXXX` und `\/` werden für die Erkennung dekodiert. Die Ausgabe bleibt gültiges JSON.
- **Gelernte Werte:** Hostnamen, Benutzer und Seriennummern werden nur gelernt, wenn sie kein CLI-Schlüsselwort oder Tabellenkopf sind (Stoppliste `regeln/strukturvorlage.json`); Hostnamen und Seriennummern brauchen zusätzlich eine Ziffer oder einen Bindestrich. Einmal gelernte Hosts, Seriennummern und Benutzer werden im ganzen Lauf ersetzt.
- **Dateinamen:** Bekannte Originalwerte werden in Pfaden auch an `-`, `_` und `.` grenzend ersetzt (`privatehost01-backup.txt` → `HOST-1-backup.txt`); der Prüfmodus meldet Reste als `Pfad-Bekannt`.
- **Eindeutige Platzhalter:** Automatisch vergebene Platzhalter überspringen alle bereits vergebenen, fest zugeordneten und als Alias reservierten. Stehen in einer geladenen Tabelle und in `festeZuordnung` verschiedene Originalwerte für denselben Platzhalter, wird die Tabelle abgelehnt (A und B).
- **Tabellenspalten** können mit `"vorkommen": 2` das zweite gleichnamige Kopfwort meinen (z. B. `Number` in `show module`).

### Geheimnisse, Pfade, Freigabe und Tabellenimport (Paket B)
- **Geheimnisse vollständig:** Werte in doppelten oder einfachen Anführungszeichen werden samt Leerzeichen und Escapes entfernt; die Anführungszeichen bleiben (`password "*****"`). Numerische und boolesche JSON-Werte werden zu `"*****"` (gültiges JSON). Zugangsdaten in URLs (`https://benutzer:passwort@host`) werden vor dem Anlegen von Zuordnungen entfernt; die Zuordnungstabelle enthält dann `https://benutzer:*****@host`.
- **Prüfmodus:** meldet teilweise maskierte Werte (`"***** Rest"`, `*****x`) als `Verdacht-Teilmaskierung`.
- **Eindeutig bezeichnete Felder** (`hostname X`, `System Name: X`, `Serial Number: X`, `user X`) werden auch mit rein alphabetischen Werten anonymisiert; nur kontextfreie Heuristiken (CLI-Prompt, Tabellenspalten) verlangen Ziffer oder Bindestrich.
- **Ein- und Ausgabe:** `anon.ps1` prüft vor jeder Änderung im Dateisystem, dass sich keine Eingabe mit dem Ausgabeordner überschneidet und die Zuordnungstabelle nicht in einer Eingabe liegt. Ergeben zwei Eingaben denselben anonymisierten Ausgabepfad (Groß-/Kleinschreibung zählt nicht), bricht der Lauf ab, bevor eine Datei geschrieben wird; `anonymisierer.html` erzeugt dann kein ZIP.
- **Exportfreigabe:** Jede Änderung an Dateien, Regeln, eigenen Begriffen, Optionen oder der Zuordnungstabelle macht das bisherige Ergebnis ungültig; ZIP und „Anonymisiert kopieren“ sind erst nach einem neuen Lauf ohne Restfunde wieder frei.
- **Tabellenimport:** Formatversion `1.0`, Pflichtabschnitte `vorwaerts`/`rueckwaerts`, nur Textwerte, beide Richtungen müssen zusammenpassen (zulässig: MAC-Normalisierung, Groß-/Kleinschreibung, Aliase umbenannter Platzhalter), keine doppelt vergebenen Platzhalter. Eine abgelehnte Tabelle wird nicht verwendet und nicht überschrieben; der bisherige Zustand bleibt.

### Benutzer in Log-Meldungen und unabhängige Nachprüfung (Folgeauftrag A2)
- **Benutzer in Meldungen:** `for user X`, `for invalid user X`, `[user: X]`, `user: X`, `snmp-server user X` und `User X logged in/failed/...` werden ersetzt. Ein so erkannter Benutzer wird danach im ganzen Lauf ersetzt, auch rückwirkend in früheren Dateien (zwei Durchläufe).
- **Mehrdeutige Benutzernamen** (CLI-Schlüsselwörter der Stoppliste und allgemeine Wörter wie `admin`, `test`, `backup`, `monitor`, `operator`, `guest`) werden nur im Feldkontext ersetzt (`user backup group ...` → `user USER-1 group ...`), nie als freies Wort (`show backup status` bleibt). `benutzerMuster` sind starke Feldmuster; `benutzerMusterSchwach` (Wert am Zeilenende, `User X logged in`) lernt keine mehrdeutigen Wörter.
- **Unabhängige Nachprüfung** (Teil des Prüfmodus, Kategorien `Nachpruefung-Benutzer`, `-Hostname`, `-Domaene`, `-Seriennummer`, `-Geheimnis`, `-SID`, `-Teilmaskierung`, `-Beschreibung`): eigene Feldregeln nach eindeutigen Feldnamen (`hostname`, `sysname`, `System-Name`, `user`, `username`, `*UserName`, `*DomainName`, `Computer`, `Serial*`, `password`, `secret`, `key`, `community`, URL mit `benutzer:passwort@`, SIDs `S-1-5-21-…`, Tabellen mit Spalte `Serial`), Beschreibungen (`description`/`alias` am Zeilenanfang, `Description:`, `Port Description :`, `Neighbor Port-Desc :`, JSON `"description"`) und Tabellen mit Beschreibungs- oder Namensspalte (`Description`/`PORT-DESC` in Schnittstellentabellen, `SYS-NAME`), unabhängig von `tabellenSpalten`. Sie nutzt weder die Lernregel noch die Stoppliste; erlaubt sind nur Platzhalter, `*****`, Werte der festen Zuordnung sowie `ausnahmen.exakteWoerter` und `pruefung.erlaubtListe`.
- **Leck-Katalog:** `tests/leck-katalog.json` sammelt alle bisher gefundenen Leckfälle. Identitätswerte dürfen nicht in der Ausgabe stehen, Geheimnisse weder in der Ausgabe noch in der Zuordnungstabelle; die Nachprüfung muss auf der Roheingabe jeden Zielwert mit passender Kategorie melden.

### E. Reihenfolge der Engine (identisch in `anon.ps1` und `anonymisierer.html`)
0. JSON-Escapes dekodieren, feste Zuordnungen reservieren; Tabellenspalten (`tabellenSpalten`) über Spaltenpositionen der Kopfzeile (Geheimnisse im Spaltenwert werden vorher entfernt)
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
11. Einmal gelernte Seriennummern und Benutzer im ganzen Text ersetzen
12. Schutz-Marker linear auflösen

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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\powershell\anon.ps1 -Pruefen -Eingabe .\tests\erwartet
```
Erwartet: Version `5.1.x`, eine Release-Nummer und `Prüfergebnis: KEINE_RESTFUNDE (Keine Restfunde nach aktivem Regelwerk)` mit Exit-Code `0`. Ein Kompilierfehler der Engine erscheint als `Add-Type`-Fehler.

Danach die vollständige Testsuite (Exit-Code `0` = alles grün):
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
```

### Regeln für Testdaten und Regex
- `tests\erwartet\` ist der committete Sollstand. `run-tests.js` vergleicht nur; neu erzeugen bei gewollter Änderung: `node tests/run-tests.js --aktualisieren`.
- In `anon-regeln.json` sind `\w`, `\d` und `\b` verboten (in .NET Unicode, in JavaScript nur ASCII). Stattdessen `[0-9]`, `[A-Za-z0-9_]`, `(?<![A-Za-z0-9_])` / `(?![A-Za-z0-9_])`. Ersetzungstexte dürfen nur `$1` bis `$9` verwenden.
- Alle `.ps1`-Dateien sind UTF-8 **mit BOM** gespeichert (sonst liest PS 5.1 sie als ANSI) und enthalten keine Gedankenstriche.

Der Ordner `tests\` enthält **87 synthetische Test- und Grenzfälle** (`tests\faelle.json`), die automatisch sowohl als LF- als auch als CRLF-Variante geprüft werden, realistische Beispieldateien (`tests\beispiele\`), erwartete Referenzausgaben (`tests\erwartet\`) sowie dedizierte Tests für alle Sicherheits- und Randfälle.

- **PowerShell-Testsuite starten:**
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
  ```
- **Node.js-Testsuite starten (für `anonymisierer.html` & Paritätstest):**
  ```bash
  node tests/run-tests.js
  ```
- **Text-Anonymisierer (`text-anonymisierer.html`, `core/text`):**
  ```bash
  node tests/run-tests-text.js
  ```
- **Browser-Test (echte UI-Handler in headless Chrome/Chromium, z. B. Exportfreigabe):**
  ```bash
  node tests/run-tests-browser.js
  ```
  Ohne Browser meldet er „NICHT AUSGEFÜHRT“; mit `BROWSER_PFLICHT=1` (CI) schlägt er dann fehl.
- **CI** (`.github/workflows/ci.yml`, `actions/checkout@v5`, `actions/setup-node@v5`): Node, Windows PowerShell 5.1 (Pflicht), PowerShell 7 und gitleaks (`.gitleaks.toml`, Allowlist nur für eindeutig erfundene Testwerte).
  - Windows PowerShell 5.1: Bei Erfolg erscheint die Zeile `TESTERGEBNIS` als Hinweis (`::notice::`); nur wenn der Testlauf fehlschlägt, werden `FEHLER`- und `TESTERGEBNIS`-Zeilen als Fehler-Annotation (`::error::`) ausgegeben.
  - gitleaks, Arbeitsstand (HEAD): Pflicht, Funde lassen den Job scheitern.
  - gitleaks, gesamte Historie: nur informativ (`continue-on-error`). Funde erscheinen als Warnung; es sind bekannte erfundene Testschlüssel aus Commit 65cd5d4 (alter Sammler), die mit einem frischen öffentlichen Repository verschwinden. Dafür gibt es keine Allowlist.
- **Sicherheitslücken melden:** siehe [`SECURITY.md`](./SECURITY.md).
- **Gemeinsamer Kern:** `core/` und `regeln/anon-regeln.json` werden mit `node tools/einbetten.js` in beide HTML-Seiten eingebettet; `node tools/einbetten.js --pruefen` (und die Testsuite) meldet Abweichungen.

---

## 9. Eingebettete Komponenten & Lizenzen

- **Lizenz des Projekts:** In [`LICENSE`](./LICENSE) ist **Apache-2.0 als Platzhalter** eingetragen. Die Entscheidung über die endgültige Lizenz ist noch **offen**.
- **ZIP- und TAR/GZIP-Verarbeitung in `anonymisierer.html`:** Direkt eingebetteter Minimal-Codec auf Basis der standardisierten Browser-APIs (`DecompressionStream`, `DataView`, `Uint8Array`, `WebCrypto API`) ohne externe Fremdbibliotheken.

### Inspiriert von
Konzepte (kein Code) wurden übernommen aus:
- [netconan](https://github.com/intentionet/netconan) (intentionet, Apache-2.0): Kategorien von Geheimnismustern, Maskenerkennung, reservierte Wörter.
- [Presidio](https://github.com/data-privacy-stack/presidio) (ursprünglich Microsoft, MIT): Erkenner mit Grundwert, Prüfziffer-Validierung, Kontextwörter und getrennte Operatoren pro Kategorie für den Reiter „Text (Datenschutz)“.

Details: [`docs/lese-auftrag-netconan-presidio.md`](./docs/lese-auftrag-netconan-presidio.md)

---

## 10. Repository-Struktur

| Ordner | Inhalt |
|---|---|
| `core/` | gemeinsamer Kern für die Browser-Seiten: `text/text-engine.js`, `tabelle/zuordnung.js` (Zuordnungstabelle, Rückübersetzung), `tabelle/krypto.js` (ANON-AES256-2) |
| `web/` | `anonymisierer.html` (Netzwerkdaten) und `text/text-anonymisierer.html` (Freitext), jeweils eine eigenständige Datei |
| `powershell/` | `anon.ps1` (Variante A, Windows PowerShell 5.1 und PowerShell 7) |
| `regeln/` | `anon-regeln.json` (Basisregelwerk, nur Beispielwerte), `strukturvorlage.json` (feste Schlüsselwortliste der Strukturvorlage) |
| `api/` | geplant: Docker-Dienst für n8n (Teil D) |
| `tests/` | `faelle.json`, `faelle-text.json`, Beispiele, Sollstand `erwartet/`, `run-tests.js`, `run-tests-text.js`, `run-tests.ps1` |
| `tools/` | `einbetten.js` (Kern und Regelwerk in die HTML-Seiten einbetten) |
| `.github/workflows/` | CI (Node, Windows PowerShell 5.1, PowerShell 7, gitleaks) |
| `docs/` | Lese-Auftrag netconan/Presidio, Datenlizenzen |

Der Sammler (`switch-sammler.ps1`) ist ein eigenes Projekt, siehe Abschnitt 3.
