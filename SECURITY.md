# Sicherheit / Security

## Sicherheitslücken melden / Reporting a vulnerability

Bitte melden Sie Sicherheitslücken **nicht** über öffentliche Issues, sondern vertraulich per E-Mail an die Projektverantwortlichen (Adresse wird vor der Veröffentlichung hier eingetragen). Bitte keine echten Konfigurationen, Logs oder Zuordnungstabellen mitschicken, nur erfundene Beispiele (`192.0.2.x`, `2001:db8::`, `example.invalid`).

Please do **not** report vulnerabilities via public issues. Contact the maintainers privately (address to be added before publication). Never attach real configurations, logs or mapping tables; use made-up examples only.

## Was als Sicherheitslücke gilt / What counts as a vulnerability

- Ein echter Wert (IP, MAC, Hostname, Seriennummer, Benutzer, Geheimnis) bleibt nach der Anonymisierung stehen **und** der Prüfmodus meldet ihn nicht (`KEINE_RESTFUNDE` trotz Rest).
- Echte Werte gelangen in die Konsole, in Fehlermeldungen, in `bericht.json` oder in den Ausgabeordner `anonym\`.
- Die Zuordnungstabelle lässt sich ohne Passwort bzw. ohne DPAPI-Schlüssel des Benutzers lesen, wird unbemerkt überschrieben oder ohne Schutz gespeichert.
- Die Browser-Seiten bauen eine Netzverbindung auf oder speichern Daten im Browser (localStorage, IndexedDB).

## Grundsätze / Design principles

- Alles läuft offline; die HTML-Seiten verbieten Netzzugriffe per Content-Security-Policy.
- Geheimnisse werden unwiderruflich durch `*****` ersetzt und stehen nicht in der Zuordnungstabelle.
- Die Zuordnungstabelle liegt nie im Ausgabeordner. Unter Windows ist sie per DPAPI oder Passwort verschlüsselt (`ANON-AES256-2`: PBKDF2-SHA256 bzw. -SHA1, AES-256-CBC, HMAC-SHA256), andernfalls nur auf ausdrücklichen Wunsch (`-Unverschluesselt`) im Klartext.
- Rückübersetzter Klartext wird nie unterhalb von `anonym\` oder im Ausgabeordner eines Laufs gespeichert.
- Das Werkzeug ersetzt keine Sichtprüfung vor der Weitergabe.

## Unterstützte Versionen / Supported versions

Bis zur ersten Veröffentlichung wird nur der aktuelle Stand des Hauptzweigs gepflegt.
