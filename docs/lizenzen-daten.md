# Lizenzen und Quellen für Daten

## Namenslisten für die Text-Pseudonymisierung (`core/text`)

Die im Text-Pseudonymisierer (`core/text`) eingebetteten Vor- und Nachnamenslisten stammen ausschließlich aus quellenoffenen Datensätzen unter gemeinfreien bzw. permissiven Lizenzen (Public Domain / CC0):

1. **Vornamen (Deutschland)**:
   - **Quelle**: Open Data der Städte Leipzig, Köln und Berlin (Melderegister Vornamenstatistik).
   - **Lizenz**: Creative Commons CC0 1.0 Universell (Public Domain Dedication).
   - **URL**: https://opendata.leipzig.de / https://offenedaten-koeln.de
   - **Verwendung**: Extrahierte Liste der häufigsten Vornamen zur Erkennung im Fließtext.

2. **Häufigste Nachnamen (Deutschland)**:
   - **Quelle**: Statistische Erhebungen und gemeinfreie linguistische Häufigkeitsdaten deutscher Familiennamen.
   - **Lizenz**: Public Domain / Gemeinfreiheit.
   - **Verwendung**: Top-Nachnamen (z. B. Müller, Schmidt, Schneider, Fischer, Weber etc.) zur Kandidatenerkennung im Fließtext.

## Ausschluss restriktiver Lizenzen
- Es werden **keine** Datensätze unter Copyleft-Lizenzen wie CC-BY-SA, ODbL oder GNU GPL in den Kerncode eingebettet.
- Die Gesamtgröße aller Listen im Browser bleibt strikt unter der Obergrenze von 40 KB.
