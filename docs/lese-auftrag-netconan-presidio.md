# Lese-Auftrag: netconan und Microsoft Presidio

Stand: 2026-10-18. Nur Konzepte, kein übernommener Code.

- **netconan** (intentionet, Apache-2.0): Anonymisierer für Netzwerk-Konfigurationen (Python).
- **Presidio** (ursprünglich Microsoft, heute `data-privacy-stack/presidio`, MIT): Erkennung und Anonymisierung personenbezogener Daten in Freitext.

## 1. Geheimnismuster, die uns fehlen

Abgleich der Kategorien aus netconan (`default_pwd_regexes.py`, `sensitive_item_removal.py`) mit `anon-regeln.json`. Geprüft mit erfundenen Beispielzeilen durch die Engine; „offen“ heißt: Das Geheimnis steht nach der Anonymisierung noch im Klartext, und der Prüfmodus meldet es nicht.

| # | Beispiel (erfunden) | Status heute |
|---|---|---|
| 1 | `ip ospf authentication-key 7 X` | offen |
| 2 | `ip ospf message-digest-key 1 md5 7 X` | offen |
| 3 | `standby 1 authentication text X` (HSRP) | offen (`md5 key-string` wird erkannt) |
| 4 | `ntp authentication-key 1 md5 X 7` | offen |
| 5 | `isis password X`, `domain-password X`, `area-password X` | offen |
| 6 | `snmp-server user u g v3 auth sha X priv aes 128 Y` | **fehlerhaft**: `128` wird als Geheimnis gelöscht, `Y` bleibt stehen |
| 7 | `snmp-server host <ip> version 2c X` (Community in der Host-Zeile) | offen |
| 8 | `simple-password X;` (Juniper) | offen |
| 9 | `ldap-login-password X` | offen |
| 10 | `radius-server host <ip> key 7 X` | offen (`radius-server key` wird erkannt) |
| 11 | `key 7 X` (alleinstehend, z. B. in `key chain`) | offen |
| 12 | `hello-authentication-key X` (IS-IS) | offen |

Bereits abgedeckt: `crypto isakmp key`, `l2tp tunnel password`, `ppp chap/pap password`, `ip ftp password`, `neighbor … password 7`, `username … secret 9`, Juniper `encrypted-password`, `authentication-key "$9$…"`, `pre-shared-key ascii-text`, `secret "$9$…"`, `digest secret`, `cable shared-secret`, `tacacs-server key`, IKEv2 `local-authentication pre-shared-key`, ASA `tunnel-group … pre-shared-key`, `wpa-psk ascii`.

Weitere Ideen aus netconan:
- **Formatgerechter Ersatz**: netconan ersetzt Cisco-Typ-7-, `$1$`-, `$6$`- und Juniper-`$9$`-Werte durch Werte im selben Format. Bei uns wird daraus `*****`; das ist für die KI eindeutiger und bleibt so.
- **Prüfmodus**: Typ-7-Werte (gerade Anzahl Hex-Zeichen nach `7 `) und `$9$…` könnten als `Verdacht-Hash` gemeldet werden, auch wenn kein Muster gegriffen hat.
- **Reservierte Wörter**: netconan schützt eine große Liste von Schlüsselwörtern vor dem Ersetzen durch „sensitive words“. Entspricht unseren `ausnahmen.exakteWoerter`; die Liste ist bei uns klein.
- **AS-Nummern**: netconan kann private und öffentliche AS-Nummern ersetzen. Bei uns bleiben `router bgp 65001` / `remote-as 64512` stehen. Das ist ein Kandidat für eine eigene Kategorie.

## 2. Vergleich der IP-Anonymisierung

| | netconan | anon.ps1 / anonymisierer.html |
|---|---|---|
| Verfahren | präfixerhaltendes Bit-Umklappen in einem Baum, gesteuert durch ein geheimes Salt (ähnlich Crypto-PAn) | Platzhalter `NET-n.Hm` je /24, Zähler in einer Zuordnungstabelle |
| Ausgabe | gültige IP-Adressen | erkennbare Platzhalter |
| Netzbeziehungen | auf allen Präfixlängen erhalten (/8 … /32), Subnetting rechnet weiter | nur innerhalb eines /24; Supernetze, Aggregation und Subnetze kleiner als /24 (z. B. /26-Grenzen) gehen verloren |
| Konsistenz über Läufe | gleiches Salt ⇒ gleiche Ausgabe, ohne Tabelle | über die weiterverwendete Zuordnungstabelle |
| Rückübersetzung | `--undo` mit Salt | mit Tabelle |
| Masken | erkannt (höchstens ein 1→0-Wechsel) und erhalten | erkannt und erhalten (Masken, Wildcards) |
| Private Netze | RFC 1918 standardmäßig erhalten (Präfix bleibt, Hostteil wird anonymisiert) | werden ersetzt; Trennung `IP-PRIV`/`IP-PUB` nur im nicht netzerhaltenden Modus |
| Host-Bits | optional erhalten (`--preserve-host-bits`) | Hostteil wird durchnummeriert, `.0` und `.255` bleiben `H0`/`H255` |
| IPv6 | präfixerhaltend, ohne Maskenerkennung | ohne Struktur (`IP6-PUB-n`) |

Bewertung:
- **Vorteil von unserem Ansatz**: Ein Platzhalter kann nicht mit einer echten Adresse verwechselt werden, und die Rückübersetzung ist eindeutig. Präfixerhaltende Verfahren sind gegen Strukturanalysen schwächer: Wer einige Originaladressen kennt, kann Teile des Baums ableiten.
- **Lücken**: Netzbeziehungen über /24 hinaus und Subnetze kleiner als /24 sind nicht sichtbar. Möglich wären eine Präfix-Notation pro Netz (z. B. `NET-3/23`) oder ein „Netzbaum“ in der Tabelle. IPv6 sollte netzerhaltend werden (`NET6-n.Hm`, je /64).

## 3. Recognizer-Modell aus Presidio für Teil E

| Presidio | Bedeutung | Anwendung auf `/core/text` |
|---|---|---|
| `PatternRecognizer` mit mehreren `Pattern(name, regex, score)` | ein Erkenner pro Entitätstyp, jedes Muster mit eigener Grundwahrscheinlichkeit | jede Kategorie (IBAN, Name, Adresse …) als Erkenner mit Mustern und Grundwert statt fester ROT/GELB-Zuordnung |
| `validate_result` / `invalidate_result` | Prüfziffer bestätigt ⇒ Höchstwert, Widerlegung ⇒ Mindestwert (verworfen) | unsere Prüfziffern (IBAN, Steuer-ID, KVNR …) setzen den Wert auf „sicher“; fehlgeschlagene Prüfziffer verwirft den Treffer |
| Kontextwörter + Verstärkung | Wörter im Umfeld (Standard: 5 davor) erhöhen den Wert um 0,35, Mindestwert 0,4 | „geb.“, „IBAN“, „Patient“ usw. heben einen Kandidaten an; ersetzt einen Teil der festen Signalwort-Regex |
| Schwellwert | Treffer unter dem Schwellwert werden verworfen | ROT = Wert ≥ hoher Schwellwert (automatisch), GELB = mittlerer Bereich (Sichtprüfung), darunter keine Anzeige |
| Allow-List / Deny-List | feste Ausnahmen bzw. feste Treffer | eigene Begriffe (Deny) und Ausnahmen (Allow) wie im Netzwerkteil |
| Auflösen von Überlappungen | bei überlappenden Treffern gewinnt der höhere Wert bzw. der längere Treffer | eindeutige Regel für Fälle wie „Dr. Hans Schmidt, Hauptstr. 5“ |
| Operator pro Entität (`replace`, `redact`, `mask`, `hash`, `encrypt`, `keep`) | getrennt von der Erkennung, pro Typ wählbar | genau unser geplanter Mechanismus pro Kategorie: `platzhalter` (= replace), `entfernen` (= redact), `generalisieren` (eigener Operator, z. B. Datum → Monat/Jahr, PLZ → erste 2 Ziffern, Alter → Altersgruppe) |
| Erklärung (`analysis_explanation`) | warum ein Treffer welchen Wert hat | Tooltip in der Farbvorschau: Muster, Grundwert, Kontextwort, Prüfziffer |

Empfehlung für Punkt 4:
- Erkennung (Erkenner, Wert) und Behandlung (Operator pro Kategorie) trennen.
- Die Stufen ROT und GELB aus Schwellwerten ableiten statt fest verdrahten.
- `generalisieren` als eigener Operator mit kategoriespezifischer Regel.
