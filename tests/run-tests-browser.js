// Browser-Test (headless Chrome/Chromium) für web/anonymisierer.html: führt die echten UI-Handler aus.
// 1. Jede relevante Änderung macht die Exportfreigabe ungültig.
// 2. Abnahmeaufgaben der Bedienoberfläche: a) erstmaliger Export, b) Verdachtsfall nachbearbeiten,
//    c) Fortsetzen mit vorhandener Zuordnung, dazu Zustandswechsel, Auftrags-/Dauerebene und Meldungen.
// 3. Korrekturen nach Praxistest: a) Verdachtsfund freigeben, b) Ersetzungsliste, c) Einzeldatei-Download,
//    d) Description in "show interface brief", dazu Sperre bei unvollständigem Lauf, verdeckte Dateinamen, Layout.
// 4. IP-Modell: Schlüsselmodus als Standard, IP-Schlüssel (.anonkey), Hinweise, Rückübersetzung, alter Modus wählbar.
// 5. Sammelentscheidungen für Fundgruppen (Auswahl, Sammelaktion, Bestätigung, Rückgängig, Zähler, Tastatur).
// Die Abläufe 1 bis 3 laufen ausdrücklich im alten IP-Modus.
//
//   node tests/run-tests-browser.js        ohne Browser: "NICHT AUSGEFÜHRT" (Exit-Code 0)
//   BROWSER_PFLICHT=1 node tests/run-tests-browser.js   ohne Browser: Exit-Code 1 (für die CI)
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const HTML_PATH = path.join(ROOT, "web", "anonymisierer.html");

function findeBrowser() {
  const kandidaten = [
    process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
  ].filter(Boolean);
  for (const k of kandidaten) if (fs.existsSync(k)) return k;
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    const r = spawnSync("which", [name], { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  }
  return null;
}

// Warten ohne virtuelle Zeit zu verbrauchen: Mit --virtual-time-budget springt die virtuelle Zeit weiter, während
// echtes Einlesen von Dateien (File.arrayBuffer/text) noch läuft. Daher meist Task-Yield (MessageChannel), nur
// gelegentlich 1 ms Timer, damit die Timer der Seite weiterlaufen.
const WARTE_HILFE = `
const __yield = () => new Promise(r => { const ch = new MessageChannel(); ch.port1.onmessage = () => r(); ch.port2.postMessage(0); });
async function bis(fn) { for (let i = 0; i < 400000; i++) { if (fn()) return true; if (i % 10 === 9) await new Promise(r => setTimeout(r, 1)); else await __yield(); } return fn(); }
// Die bestehenden Abläufe (1 bis 3) laufen ausdrücklich im alten IP-Modus (Platzhalter NET-n.Hm); Ablauf 4 prüft den Schlüsselmodus
function alterIpModus() {
  const r = document.getElementById("optIpModusPlatzhalter");
  if (!r) { window.__fehler.push("Auswahl optIpModusPlatzhalter fehlt"); return; }
  r.checked = true;
  r.dispatchEvent(new Event("change", { bubbles: true }));
}
`;

// Testskript, das in eine Kopie der Seite eingefügt wird (nutzt nur die vorhandenen Bedienelemente)
const PROBE = `<script>
${WARTE_HILFE}
window.__fehler = [];
window.addEventListener("error", e => window.__fehler.push(String(e.message)));
window.alert = () => {};
window.confirm = () => true;
const warte = (ms) => new Promise(r => setTimeout(r, ms));
const zip = () => !document.getElementById("btnDownloadZip").disabled;
const kopie = () => !document.getElementById("btnCopyAnon").disabled;
const datei = async (name, inhalt) => {
  const info = document.getElementById("fileCountInfo");
  info.textContent = "";
  const dt = new DataTransfer();
  dt.items.add(new File([inhalt], name, { type: "text/plain" }));
  const inp = document.getElementById("inputFiles");
  inp.files = dt.files;
  inp.dispatchEvent(new Event("change"));
  // Einlesen ist asynchron: warten, bis die Seite die Dateien als bereit meldet
  await bis(() => /bereit/.test(info.textContent));
};
async function lauf() {
  const banner = document.getElementById("auditBanner");
  banner.textContent = "";
  document.getElementById("btnRunAnon").click();
  await bis(() => /Prüfergebnis/.test(banner.textContent));
  await warte(50);
}
window.addEventListener("load", async () => {
  alterIpModus();
  const schritte = [];
  const merke = (name) => schritte.push({ name, zip: zip(), kopie: kopie() });
  try {
    await datei("a.txt", "hostname brw-host01\\nip address 192.0.2.10/24\\n");
    await lauf(); merke("lauf");
    await datei("b.txt", "uptime 3 days\\n"); merke("datei-hinzugefuegt");
    await lauf(); merke("lauf");
    document.getElementById("btnResetTableState").click(); await warte(50); merke("tabelle-zurueckgesetzt");
    await lauf(); merke("lauf");
    document.getElementById("btnShowTableOriginals").click(); await warte(50);
    document.getElementById("tableAddOriginal").value = "brw-extra01";
    document.getElementById("btnTableAddEntry").click(); await warte(50); merke("tabelle-geaendert");
    await lauf(); merke("lauf");
    const regeln = document.getElementById("rulesTextarea");
    regeln.value = regeln.value + " "; regeln.dispatchEvent(new Event("input")); await warte(50); merke("regeln-geaendert");
    await lauf(); merke("lauf");
    const opt = document.getElementById("optNetzerhaltend");
    opt.checked = !opt.checked; opt.dispatchEvent(new Event("change")); await warte(50); merke("option-geaendert");
    await lauf(); merke("lauf");
    const muster = document.getElementById("eigeneHostnamenMusterInput");
    muster.value = "(?i)(brw-[a-z]+[0-9]+)"; muster.dispatchEvent(new Event("input")); await warte(50); merke("eigene-begriffe-geaendert");
    document.getElementById("btnClearAll").click(); await warte(50); merke("alles-geleert");
  } catch (e) { window.__fehler.push("Probe: " + e.message); }
  const out = document.createElement("pre");
  out.id = "__probe";
  out.textContent = JSON.stringify({ fehler: window.__fehler, schritte });
  document.body.appendChild(out);
});
</script>
</body>`;

// Abnahmeaufgaben a-c, Zustandswechsel, Auftrags- und Dauerebene, Meldungen ohne alert() (nur erfundene Werte)
const PROBE_ABLAUF = `<script>
${WARTE_HILFE}
window.__fehler = [];
window.__alerts = 0;
window.addEventListener("error", e => window.__fehler.push(String(e.message)));
window.alert = () => { window.__alerts++; };
window.confirm = () => true;
const blobs = [];
const origUrl = URL.createObjectURL.bind(URL);
URL.createObjectURL = (b) => { blobs.push(b); return origUrl(b); };
const warte = (ms) => new Promise(r => setTimeout(r, ms));
const $ = (id) => document.getElementById(id);
const pruefungen = [];
const pruefe = (name, ok, detail) => pruefungen.push({ name, ok: Boolean(ok), detail: detail === undefined ? "" : String(detail) });
const code = () => $("ablaufStatus").dataset.code;
const zip = () => !$("btnDownloadZip").disabled;
async function dateien(liste) {
  const info = $("fileCountInfo");
  info.textContent = "";
  const dt = new DataTransfer();
  for (const [name, inhalt] of liste) dt.items.add(new File([inhalt], name, { type: "text/plain" }));
  const inp = $("inputFiles");
  inp.files = dt.files;
  inp.dispatchEvent(new Event("change"));
  await bis(() => /bereit/.test(info.textContent));
}
async function lauf(knopf) {
  const banner = $("auditBanner");
  banner.textContent = "";
  $(knopf || "btnRunAnon").click();
  await bis(() => /Prüfergebnis/.test(banner.textContent));
  await warte(50);
}
function karte(wert) { return Array.from(document.querySelectorAll(".fundkarte")).find(k => k.querySelector(".fk-kontext") && k.querySelector(".fk-kontext").textContent.indexOf(wert) >= 0); }
function anonText() { return Array.from(document.querySelectorAll("#previewAnon .vz-text")).map(t => t.textContent).join("\\n"); }
function zuruecksetzen() { $("btnClearAll").click(); }
const LECK = '<Data Name="TargetUserName">jdoe7</Data>\\nhostname brw-host01\\n';

window.addEventListener("load", async () => {
  alterIpModus();
  try {
    // a) Erstmaliger Export: laden, verarbeiten, Funde entscheiden, Download erst danach
    pruefe("a: vor dem Laden neutral, nicht grün", code() === "KEINE_DATEIEN" && !$("ablaufStatus").classList.contains("ok"), code());
    await dateien([["a.log", LECK]]);
    pruefe("a: nach dem Laden 'Noch nicht geprüft'", code() === "NICHT_GEPRUEFT" && $("ablaufStatus").textContent === "Noch nicht geprüft", code());
    pruefe("a: Dateiliste zeigt Datei mit Status bereit", /1 geladen, 1 bereit/.test($("dateiZusammenfassung").textContent), $("dateiZusammenfassung").textContent);
    await lauf();
    const kA = karte("jdoe7");
    pruefe("a: Fundkarte 'Möglicher Benutzername' mit Kontext und Fundort", kA && /Möglicher Benutzername/.test(kA.textContent) && kA.querySelector("mark.markiert-fund") && kA.querySelector(".fund-ort"), kA ? kA.textContent.slice(0, 80) : "keine Karte");
    pruefe("a: offene Fundgruppe sperrt den Download mit Grund", code() === "OFFENE_FUNDE" && !zip() && /Gesperrt: .+Nächster Schritt/.test($("releaseLockInfo").textContent), $("releaseLockInfo").textContent);
    pruefe("a: Schritt 3 ist nach dem Lauf aktiv", $("schritt-3").classList.contains("active"));
    kA.querySelector('button[data-aktion="unveraendert"]').click();
    await warte(50);
    const kA2 = karte("jdoe7");
    pruefe("a: 'Unverändert lassen' zeigt sofort den Warnhinweis", kA2 && /Dieser Wert bleibt in den weiterzugebenden Dateien sichtbar\\./.test(kA2.textContent));
    pruefe("a: nach der Entscheidung 'veraltet', Download weiter gesperrt", code() === "VERALTET" && !zip(), code());
    $("btnApplyFindingDecisions").click();
    await bis(() => code() === "KEINE_RESTFUNDE");
    pruefe("a: nach dem Neu-Verarbeiten frei, freigegebener Wert gezählt", code() === "KEINE_RESTFUNDE" && zip() && /bewusst freigegeben/.test($("auditBanner").textContent), $("auditBanner").textContent);
    $("btnDownloadReport").click();
    await warte(100);
    const bericht = JSON.parse(await blobs[blobs.length - 1].text());
    pruefe("a: technischer Bericht zählt bewusst freigegebene Werte, ohne Werte", bericht.bewusstFreigegeben === 1 && JSON.stringify(bericht).indexOf("jdoe7") < 0 && bericht.pruefergebnis === "KEINE_RESTFUNDE", JSON.stringify(bericht.bewusstFreigegeben));
    $("btnDownloadZip").click();
    await warte(100);
    pruefe("a: Ergebnis-ZIP wird erzeugt", blobs.length >= 2 && blobs[blobs.length - 1].type === "application/zip");

    // Zustandswechsel: Datei hinzufügen, Datei entfernen, Einstellung ändern -> veraltet
    await dateien([["b.log", "uptime 3 days\\n"]]);
    pruefe("Zustand: Datei hinzugefügt -> 'Ergebnis veraltet'", code() === "VERALTET" && !zip() && $("ablaufStatus").textContent === "Ergebnis veraltet – erneut verarbeiten", code());
    await lauf();
    pruefe("Zustand: erneut verarbeitet -> frei", code() === "KEINE_RESTFUNDE" && zip(), code());
    const entf = Array.from(document.querySelectorAll("#dateiListeBody button")).pop();
    entf.click();
    await warte(50);
    pruefe("Zustand: Datei entfernt -> 'Ergebnis veraltet'", code() === "VERALTET" && !zip(), code());
    await lauf();
    const cb = document.querySelector('.cat-toggle[value="benutzer"]');
    cb.checked = false; cb.dispatchEvent(new Event("change"));
    await warte(50);
    pruefe("Zustand: Einstellung geändert -> 'Ergebnis veraltet'", code() === "VERALTET" && !zip(), code());
    pruefe("Einstellungen: Abweichung immer sichtbar", /Benutzernamen werden nicht ersetzt/.test($("einstellungsZusammenfassung").textContent), $("einstellungsZusammenfassung").textContent);
    cb.checked = true; cb.dispatchEvent(new Event("change"));
    await warte(50);
    // Dieser Ablauf läuft ausdrücklich im alten IP-Modus: das ist danach die einzige Abweichung vom Standard
    const abwListe = Array.from($("einstellungsZusammenfassung").querySelectorAll("li.abweichung")).map(li => li.textContent).filter(t => !/eigene Ersetzung|bewusst freigegeben|nur für diesen Auftrag/.test(t));
    pruefe("Einstellungen: Standard wieder hergestellt (nur der alte IP-Modus weicht ab)", abwListe.length === 1 && /alter Modus/.test(abwListe[0]) && !/Benutzernamen werden nicht ersetzt/.test($("einstellungsZusammenfassung").textContent), abwListe.join(" | "));

    // "nur dieser Auftrag" wirkt nach dem Zurücksetzen nicht mehr
    zuruecksetzen();
    await warte(50);
    pruefe("Zurücksetzen: Status wieder neutral", code() === "KEINE_DATEIEN", code());
    await dateien([["a.log", LECK]]);
    await lauf();
    pruefe("Auftrag: nach dem Zurücksetzen wird der Wert wieder gemeldet", code() === "OFFENE_FUNDE" && Boolean(karte("jdoe7")), code());
    await dateien([["c.log", "uptime 3 days\\n"]]);
    pruefe("Zustand: Datei hinzugefügt bei offenen Funden -> 'Ergebnis veraltet' statt alter Fundgruppen", code() === "VERALTET", code());
    Array.from(document.querySelectorAll("#dateiListeBody button")).pop().click();
    await lauf();
    pruefe("Zustand: nach erneutem Verarbeiten wieder offene Fundgruppe", code() === "OFFENE_FUNDE" && Boolean(karte("jdoe7")), code());

    // Rückgängig und dauerhafte Regel
    karte("jdoe7").querySelector('button[data-aktion="ersetzen"]').click();
    await warte(50);
    pruefe("Rückgängig: Entscheidung steht in der Liste", /Alle Vorkommen ersetzen/.test($("entscheidungsListe").textContent));
    karte("jdoe7").querySelector('button[data-aktion="rueckgaengig"]').click();
    await warte(50);
    pruefe("Rückgängig: Karte wieder offen", code() === "OFFENE_FUNDE" && karte("jdoe7").querySelector('button[data-aktion="unveraendert"]') && /Noch keine Entscheidungen/.test($("entscheidungsListe").textContent));
    const kD = karte("jdoe7");
    const radioD = kD.querySelector('input[value="dauerhaft"]');
    radioD.checked = true; radioD.dispatchEvent(new Event("change"));
    pruefe("Dauerhaft: Hinweis 'Regeldatei speichern' bei Auswahl", Array.from(kD.querySelectorAll(".fk-warnung")).some(w => !w.hidden && /Regeldatei speichern, sonst geht die Regel beim Schließen verloren/.test(w.textContent)));
    kD.querySelector('button[data-aktion="unveraendert"]').click();
    await warte(50);
    pruefe("Dauerhaft: Freigabe in den Einstellungen sichtbar", /Benutzername: jdoe7/.test($("freigabenListe").textContent) && !$("dauerhaftHinweis").hidden && !$("lokalUngespeichert").hidden, $("freigabenListe").textContent);
    $("btnApplyFindingDecisions").click();
    await bis(() => code() === "KEINE_RESTFUNDE");
    pruefe("Dauerhaft: nach Neu-Verarbeiten frei", code() === "KEINE_RESTFUNDE", code());
    zuruecksetzen();
    await dateien([["a.log", LECK]]);
    await lauf();
    pruefe("Dauerhaft: wirkt auch nach dem Zurücksetzen", code() === "KEINE_RESTFUNDE", code());
    $("btnDownloadLocalTerms").click();
    await warte(100);
    const lokal = JSON.parse(await blobs[blobs.length - 1].text());
    pruefe("Dauerhaft: anon-regeln.lokal.json enthält die kategoriegebundene Freigabe", lokal.ausnahmen && lokal.ausnahmen.freigegeben && lokal.ausnahmen.freigegeben[0].kategorie === "Benutzer" && lokal.ausnahmen.freigegeben[0].wert === "jdoe7");
    pruefe("Dauerhaft: nach dem Speichern kein Hinweis mehr", $("lokalUngespeichert").hidden && $("dauerhaftHinweis").hidden);
    $("freigabenListe").querySelector("button").click();
    await warte(50);

    // b) Verdachtsfall nachbearbeiten: Fund anklicken -> Stelle (hinter 200 KB) -> alle ersetzen -> neu verarbeiten -> Fund weg
    zuruecksetzen();
    const filler = [];
    for (let i = 0; i < 25000; i++) filler.push("interface 1/1/1 speed auto");
    filler.push('<Data Name="TargetUserName">kmeier8</Data>');
    await dateien([["gross.log", filler.join("\\n") + "\\n"]]);
    await lauf();
    const kB = karte("kmeier8");
    pruefe("b: Fund in großer Datei erkannt", Boolean(kB) && code() === "OFFENE_FUNDE", code());
    kB.querySelector(".fund-ort").click();
    await warte(100);
    const zielZeile = document.querySelector('#previewAnon .vz[data-zeile="25001"]');
    pruefe("b: Klick springt zur Zeile 25001 (außerhalb der ersten 200 KB)", zielZeile && zielZeile.classList.contains("ziel"), $("vorschauInfo").textContent);
    pruefe("b: Wert an der Fundstelle markiert", zielZeile && zielZeile.querySelector("mark.markiert-fund") && zielZeile.querySelector("mark.markiert-fund").textContent === "kmeier8");
    pruefe("b: Vorschau zeigt nur einen Ausschnitt", /Ausschnitt/.test($("vorschauInfo").textContent) && document.querySelectorAll("#previewAnon .vz").length < 25001, $("vorschauInfo").textContent);
    pruefe("b: Originalspalte standardmäßig verdeckt (nicht im DOM)", $("originalSpalte").hidden && $("previewOriginal").textContent === "");
    karte("kmeier8").querySelector('button[data-aktion="ersetzen"]').click();
    await warte(50);
    $("btnApplyFindingDecisions").click();
    await bis(() => code() === "KEINE_RESTFUNDE");
    pruefe("b: nach 'Alle ersetzen' und Neu-Verarbeiten ist der Fund weg", !karte("kmeier8") && code() === "KEINE_RESTFUNDE" && zip(), code());
    $("btnNaechsteAenderung").click();
    await warte(100);
    pruefe("b: 'Nächste Änderung' springt zur ersetzten Stelle", /SW-EIGEN-1/.test(document.querySelector("#previewAnon .vz.ziel") ? document.querySelector("#previewAnon .vz.ziel").textContent : ""), document.querySelector("#previewAnon .vz.ziel") ? document.querySelector("#previewAnon .vz.ziel").dataset.zeile : "-");
    $("optNurGeaendert").checked = true; $("optNurGeaendert").dispatchEvent(new Event("change"));
    await warte(50);
    pruefe("b: 'Nur geänderte Zeilen' blendet unveränderte Zeilen aus", document.querySelectorAll("#previewAnon .vz").length === 1, document.querySelectorAll("#previewAnon .vz").length);
    $("optNurGeaendert").checked = false; $("optNurGeaendert").dispatchEvent(new Event("change"));
    $("vorschauSuche").value = "SW-EIGEN";
    $("btnVorschauSuche").click();
    await warte(50);
    pruefe("b: Suche in der Datei markiert Treffer", document.querySelectorAll("#previewAnon mark.treffer").length >= 1);
    $("vorschauSuche").value = "";
    $("optOriginalAnzeigen").checked = true; $("optOriginalAnzeigen").dispatchEvent(new Event("change"));
    await warte(50);
    pruefe("b: Originalspalte nur nach Einschalten sichtbar", !$("originalSpalte").hidden && document.querySelectorAll("#previewOriginal .vz").length > 0);
    $("optOriginalAnzeigen").checked = false; $("optOriginalAnzeigen").dispatchEvent(new Event("change"));

    // c) Fortsetzen mit vorhandener Zuordnung: Tabelle laden -> neue Datei -> gleiche Werte, gleiche Platzhalter
    zuruecksetzen();
    const tabState = new AnonState();
    const tabCfg = buildEngineConfig(DEFAULT_RULES, { netzerhaltend: true, ipModus: "platzhalter" });
    processText("hostname brw-host01\\ninterface vlan 5\\n ip address 192.0.2.10/24\\n", tabCfg, tabState);
    const tabJson = JSON.stringify(tabState.toJSON());
    $("zuordnungLaden").checked = true; $("zuordnungLaden").dispatchEvent(new Event("change"));
    pruefe("c: 'Vorhandene Zuordnung laden' zeigt Passwort und Dateiauswahl", !$("zuordnungLadenBox").hidden && $("zuordnungNeuBox").hidden);
    const dtT = new DataTransfer();
    dtT.items.add(new File([tabJson], "zuordnung.json", { type: "application/json" }));
    $("inputTableFile").files = dtT.files;
    $("inputTableFile").dispatchEvent(new Event("change"));
    await bis(() => /geladen/.test($("tableLoadStatus").textContent));
    pruefe("c: Zuordnungstabelle geladen", /Zuordnungstabelle geladen \\(/.test($("tableLoadStatus").textContent), $("tableLoadStatus").textContent);
    await dateien([["neu.cfg", "hostname brw-host01\\ninterface vlan 5\\n ip address 192.0.2.10/24\\n ip address 192.0.2.77/24\\n"]]);
    await lauf();
    const ausgabe = anonText();
    const zurueck = deanonymizeText(ausgabe, tabState);
    pruefe("c: gleiche Werte bekommen die Platzhalter der geladenen Zuordnung", ausgabe.indexOf("brw-host01") < 0 && /hostname brw-host01/.test(zurueck) && /ip address 192\\.0\\.2\\.10\\/24/.test(zurueck), ausgabe.split("\\n")[0]);
    pruefe("c: neuer Wert bekommt einen neuen Platzhalter", ausgabe.indexOf("192.0.2.77") < 0 && zurueck.indexOf("192.0.2.77") < 0);
    pruefe("c: Hinweis 'Zuordnung seit dem letzten Speichern geändert'", !$("tabelleGeaendertHinweis").hidden);

    // Meldungen an der betroffenen Stelle statt alert()
    $("tableSavePass").value = "kurz";
    $("tableSavePassConfirm").value = "kurz";
    $("btnExportEncryptedTable").click();
    await warte(50);
    pruefe("Meldung: zu kurzes Passwort am Passwortfeld", $("tableSavePassMeldung").textContent.length > 0 && $("tableSavePass").getAttribute("aria-invalid") === "true");
    zuruecksetzen();
    $("btnRunAnon").click();
    await warte(50);
    pruefe("Meldung: ohne Dateien Hinweis in Schritt 2", /keine Dateien geladen/i.test($("laufMeldung").textContent) && $("schritt-2").classList.contains("active"), $("laufMeldung").textContent);
    const fo = document.querySelector("#festeZuordnungRows .feste-orig-input");
    const fp = document.querySelector("#festeZuordnungRows .feste-ph-input");
    fo.value = "brw-x1"; fp.value = "kleinbuchstaben"; fo.dispatchEvent(new Event("input"));
    await warte(50);
    pruefe("Meldung: fehlerhafte Zeile bei eigenen Ersetzungen markiert", fp.getAttribute("aria-invalid") === "true" || fo.getAttribute("aria-invalid") === "true", $("customTermsValidationMsg").textContent);
    fo.value = ""; fp.value = ""; fo.dispatchEvent(new Event("input"));
    pruefe("Navigation: Hauptnavigation mit drei Bereichen", document.querySelectorAll("nav.tabs button").length === 3);
    pruefe("Navigation: vier frei anspringbare Schritte", document.querySelectorAll("nav.schritte button").length === 4);
    document.querySelector('nav.schritte button[data-schritt="4"]').click();
    pruefe("Navigation: Schritt 4 direkt anspringbar", $("schritt-4").classList.contains("active") && document.querySelector('nav.schritte button[data-schritt="4"]').getAttribute("aria-current") === "step");
  } catch (e) { window.__fehler.push("Probe: " + e.message + " " + (e.stack || "").split("\\n")[1]); }
  const out = document.createElement("pre");
  out.id = "__probe";
  out.textContent = JSON.stringify({ fehler: window.__fehler, alerts: window.__alerts, pruefungen });
  document.body.appendChild(out);
});
</script>
</body>`;

const PROBE_KORREKTUR = `<script>
${WARTE_HILFE}
window.__fehler = [];
window.__alerts = 0;
window.addEventListener("error", e => window.__fehler.push(String(e.message)));
window.alert = () => { window.__alerts++; };
window.confirm = () => true;
const blobs = [];
const namen = [];
const origUrl = URL.createObjectURL.bind(URL);
URL.createObjectURL = (b) => { blobs.push(b); return origUrl(b); };
const origKlick = HTMLAnchorElement.prototype.click;
HTMLAnchorElement.prototype.click = function () { if (this.download) namen.push(this.download); return origKlick.call(this); };
const warte = (ms) => new Promise(r => setTimeout(r, ms));
const $ = (id) => document.getElementById(id);
const pruefungen = [];
const pruefe = (name, ok, detail) => pruefungen.push({ name, ok: Boolean(ok), detail: detail === undefined ? "" : String(detail) });
const code = () => $("ablaufStatus").dataset.code;
const zip = () => !$("btnDownloadZip").disabled;
async function dateien(liste) {
  const info = $("fileCountInfo");
  info.textContent = "";
  const dt = new DataTransfer();
  for (const [name, inhalt] of liste) dt.items.add(new File([inhalt], name, { type: "application/octet-stream" }));
  const inp = $("inputFiles");
  inp.files = dt.files;
  inp.dispatchEvent(new Event("change"));
  await bis(() => /bereit/.test(info.textContent));
}
async function lauf() {
  const banner = $("auditBanner");
  banner.textContent = "";
  $("btnRunAnon").click();
  await bis(() => /Prüfergebnis/.test(banner.textContent));
  await warte(50);
}
function karten() { return Array.from(document.querySelectorAll(".fundkarte")); }
function karte(wert) { return karten().find(k => k.querySelector(".fk-kontext") && k.querySelector(".fk-kontext").textContent.indexOf(wert) >= 0); }
function anonText() { return Array.from(document.querySelectorAll("#previewAnon .vz-text")).map(t => t.textContent).join("\\n"); }
function zuruecksetzen() { $("btnClearAll").click(); }
const BUILD = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
const SEP = "-".repeat(90);
const BRIEF = [SEP, "Port      Native  Type           Status  Reason                  Speed   Description", SEP,
  "1/1/1     1       1GbT           up                              1000    Uplink-Weber",
  "1/1/2     1       1GbT           up                              1000    Drucker-Etage2-Weber", ""].join("\\n");

window.addEventListener("load", async () => {
  alterIpModus();
  try {
    // a) Verdachtsfund (Build-ID) ist keine Sackgasse: Bestätigung -> Unverändert lassen -> Download frei
    await dateien([["brw-sw07.txt", "ArubaOS-CX build id " + BUILD + "\\nhostname brw-sw07\\n<Data Name=\\"TargetUserName\\">jdoe7</Data>\\n"]]);
    pruefe("Dateiliste: vor dem Verarbeiten verdeckt ('Datei n'), kein Originalname", /^Datei [0-9]+$/.test(document.querySelector("#dateiListeBody td").textContent) && $("dateiListeBody").textContent.indexOf("brw-sw07") < 0, document.querySelector("#dateiListeBody td").textContent);
    $("btnDateinamenOriginale").click();
    pruefe("Dateiliste: Original nur nach 'Originale anzeigen'", document.querySelector("#dateiListeBody td").textContent === "brw-sw07.txt");
    $("btnDateinamenOriginale").click();
    await lauf();
    const kV = karte(BUILD);
    pruefe("a: Build-ID als Verdacht gemeldet", kV && /Verdacht auf Passwort oder Schlüssel/.test(kV.textContent) && code() === "OFFENE_FUNDE", kV ? kV.querySelector(".fk-titel").textContent : "keine Karte");
    pruefe("a: jede Fundgruppe hat mindestens zwei Aktionen", karten().length > 0 && karten().every(k => k.querySelectorAll("button[data-aktion]").length >= 2), karten().map(k => k.querySelectorAll("button[data-aktion]").length).join(","));
    const bU = kV.querySelector('button[data-aktion="unveraendert"]');
    pruefe("a: Verdacht bietet 'Unverändert lassen' und 'Als Geheimnis maskieren'", bU && kV.querySelector('button[data-aktion="maskieren"]') && /Als Geheimnis maskieren \\(\\*\\*\\*\\*\\*\\)/.test(kV.textContent));
    pruefe("a: 'Unverändert lassen' erst nach Bestätigung 'Ich habe geprüft: kein Geheimnis'", bU.disabled && /Ich habe geprüft: kein Geheimnis/.test(kV.textContent));
    const best = kV.querySelector("input[data-bestaetigung]");
    best.checked = true; best.dispatchEvent(new Event("change"));
    pruefe("a: nach Bestätigung freigebbar", !bU.disabled);
    karte("jdoe7").querySelector('button[data-aktion="ersetzen"]').click();
    await warte(50);
    const kV2 = karte(BUILD);
    pruefe("Fix 4: Häkchen 'kein Geheimnis' bleibt nach Entscheidung einer anderen Fundgruppe erhalten", kV2.querySelector("input[data-bestaetigung]").checked && !kV2.querySelector('button[data-aktion="unveraendert"]').disabled);
    kV2.querySelector('button[data-aktion="unveraendert"]').click();
    await warte(50);
    pruefe("Layout: Getroffene Entscheidungen aufgeklappt, sobald vorhanden", $("entscheidungenDetails").open && $("entscheidungenAnzahl").textContent !== "0", $("entscheidungenAnzahl").textContent);
    $("btnApplyFindingDecisions").click();
    await bis(() => code() === "KEINE_RESTFUNDE");
    pruefe("a: nach Neu-Verarbeiten Download frei, Freigabe gezählt", code() === "KEINE_RESTFUNDE" && zip() && /1 bewusst freigegeben/.test($("auditBanner").textContent), $("auditBanner").textContent);
    pruefe("Layout: leerer Bereich 'Alle Einzelfunde' eingeklappt", !$("einzelfundeDetails").open && $("einzelfundeAnzahl").textContent === "0", $("einzelfundeAnzahl").textContent);
    pruefe("Dateiliste: nach dem Verarbeiten anonymisierter Name", document.querySelector("#dateiListeBody td").textContent === "HOST-1.txt", document.querySelector("#dateiListeBody td").textContent);

    // c) Einzeldatei: Hauptknopf bei nur einer Datei, Vorschau-Knopf, Inhalt anonymisiert
    pruefe("c: bei nur einer Datei ist der Einzel-Download der Hauptknopf", !$("btnDownloadEinzelHaupt").hidden && !$("btnDownloadEinzelHaupt").disabled && $("btnDownloadEinzelHaupt").classList.contains("success") && !$("btnDownloadZip").classList.contains("success"));
    $("btnDownloadEinzeln").click();
    await warte(100);
    const inhalt = await blobs[blobs.length - 1].text();
    pruefe("c: 'Diese Datei herunterladen' liefert den anonymisierten Inhalt", inhalt.indexOf("brw-sw07") < 0 && inhalt.indexOf(BUILD) >= 0 && /hostname HOST-1/.test(inhalt), inhalt.split("\\n")[1]);
    pruefe("c: anonymisierter Dateiname mit ursprünglichem Dateityp", namen[namen.length - 1] === "HOST-1.txt", namen[namen.length - 1]);

    // b) Ersetzungsliste: Einträge mit Anzahl, Originale verdeckt, Sprung zur Stelle
    $("reiterErsetzungen").click();
    await warte(50);
    const zeile = Array.from(document.querySelectorAll("#mappingPreviewTableBody tr")).find(tr => tr.dataset.ph === "HOST-1");
    pruefe("b: Ersetzungsliste zeigt HOST-1 mit Anzahl", !$("tablePreviewCard").hidden && zeile && /^1\\b/.test(zeile.querySelector(".map-anzahl-cell").textContent), zeile ? zeile.textContent : "keine Zeile");
    pruefe("b: Originale standardmäßig verdeckt (nicht im DOM)", $("mappingPreviewTableBody").textContent.indexOf("brw-sw07") < 0);
    zeile.querySelector(".map-jump-btn").click();
    await warte(100);
    const ziel = document.querySelector("#previewAnon .vz.ziel");
    pruefe("b: 'Zur Stelle' springt zur ersten Stelle in der Vorschau", ziel && ziel.dataset.zeile === "2" && ziel.querySelector("mark.markiert-fund") && ziel.querySelector("mark.markiert-fund").textContent === "HOST-1", ziel ? ziel.dataset.zeile : "-");
    $("btnShowTableOriginals").click();
    await warte(50);
    pruefe("b: 'Originale anzeigen' zeigt Original und Bearbeiten", $("mappingPreviewTableBody").textContent.indexOf("brw-sw07") >= 0 && document.querySelector("#mappingPreviewTableBody .map-rename-btn") && document.querySelector("#mappingPreviewTableBody .map-remove-btn"));
    document.querySelector('nav.schritte button[data-schritt="4"]').click();
    pruefe("b: beim Verlassen von Schritt 3 wieder verdeckt", $("mappingPreviewTableBody").textContent.indexOf("brw-sw07") < 0);
    document.querySelector('nav.schritte button[data-schritt="3"]').click();
    $("reiterFunde").click();
    $("optVorschauUnten").checked = true; $("optVorschauUnten").dispatchEvent(new Event("change"));
    pruefe("Layout: Vorschau umschaltbar unter die Funde", $("pruefGrid").classList.contains("untereinander"));
    $("optVorschauUnten").checked = false; $("optVorschauUnten").dispatchEvent(new Event("change"));

    // d) Description in "show interface brief" (ohne Spalten Mode/Enabled) wird ersetzt
    zuruecksetzen();
    await dateien([["brief.txt", BRIEF]]);
    await lauf();
    const aus = anonText();
    pruefe("d: Description in show interface brief ersetzt", aus.indexOf("Weber") < 0 && /1000    TEXT-1/.test(aus) && code() === "KEINE_RESTFUNDE", aus.split("\\n")[3]);

    // Sicher erkanntes Geheimnis: nur maskieren oder Datei entfernen (keine Sackgasse)
    zuruecksetzen();
    const cb = document.querySelector('.cat-toggle[value="geheimnisseEntfernen"]');
    cb.checked = false; cb.dispatchEvent(new Event("change"));
    await dateien([["cfg.txt", "hostname HOST-9\\n password plain Klartext77\\n"]]);
    await lauf();
    const kG = karten().find(k => /sicher erkannt/.test(k.textContent));
    pruefe("Geheimnis: sicher erkannt ohne 'Unverändert lassen', mit Maskieren und Datei entfernen", kG && !kG.querySelector('button[data-aktion="unveraendert"]') && kG.querySelector('button[data-aktion="ersetzen"]') && kG.querySelector('button[data-aktion="datei-entfernen"]'), kG ? Array.from(kG.querySelectorAll("button[data-aktion]")).map(b => b.dataset.aktion).join(",") : "keine Karte");
    kG.querySelector('button[data-aktion="datei-entfernen"]').click();
    await warte(50);
    pruefe("Geheimnis: 'Datei aus dem Auftrag entfernen' entfernt die Datei", /0 geladen/.test($("dateiZusammenfassung").textContent) && code() === "KEINE_DATEIEN", code());
    cb.checked = true; cb.dispatchEvent(new Event("change"));

    // Unvollständiger Lauf sperrt den Download (ZIP und Einzeldateien)
    zuruecksetzen();
    const pcap = new Uint8Array(64); pcap.set([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]);
    await dateien([["a.txt", "uptime 3 days\\n"], ["b.txt", "uptime 4 days\\n"], ["mitschnitt.pcap", pcap]]);
    await lauf();
    pruefe("Unvollständig: Download gesperrt", code() === "UNVOLLSTAENDIG" && !zip() && $("btnDownloadEinzeln").disabled && document.querySelectorAll(".einzel-download-btn").length === 2 && Array.from(document.querySelectorAll(".einzel-download-btn")).every(b => b.disabled), code());
    pruefe("Unvollständig: Grund und nächster Schritt angezeigt", /Gesperrt: .*nicht verarbeitet.*Nächster Schritt: .*entfernen/.test($("releaseLockInfo").textContent), $("releaseLockInfo").textContent);
    Array.from(document.querySelectorAll("#dateiListeBody button")).pop().click();
    await lauf();
    pruefe("Unvollständig: nach Entfernen und Neu-Verarbeiten frei, Liste mit Einzel-Downloads", code() === "KEINE_RESTFUNDE" && zip() && $("btnDownloadEinzelHaupt").hidden && document.querySelectorAll(".einzel-download-btn").length === 2 && Array.from(document.querySelectorAll(".einzel-download-btn")).every(b => !b.disabled), code());
    document.querySelectorAll(".einzel-download-btn")[1].click();
    await warte(100);
    pruefe("c: Einzel-Download aus der Liste in Schritt 4", (await blobs[blobs.length - 1].text()) === "uptime 4 days\\n");
  } catch (e) { window.__fehler.push("Probe: " + e.message + " " + (e.stack || "").split("\\n")[1]); }
  const out = document.createElement("pre");
  out.id = "__probe";
  out.textContent = JSON.stringify({ fehler: window.__fehler, alerts: window.__alerts, pruefungen });
  document.body.appendChild(out);
});
</script>
</body>`;

// 4. IP-Modell: Schlüsselmodus als Standard, IP-Schlüssel laden/erzeugen/speichern, Hinweise, Rückübersetzung
const PROBE_IPMODELL = `<script>
${WARTE_HILFE}
window.__fehler = [];
window.__alerts = 0;
window.addEventListener("error", e => window.__fehler.push(String(e.message)));
window.alert = () => { window.__alerts++; };
window.confirm = () => true;
const blobs = [];
const namen = [];
const origUrl = URL.createObjectURL.bind(URL);
URL.createObjectURL = (b) => { blobs.push(b); return origUrl(b); };
const origKlick = HTMLAnchorElement.prototype.click;
HTMLAnchorElement.prototype.click = function () { if (this.download) namen.push(this.download); return origKlick.call(this); };
const warte = (ms) => new Promise(r => setTimeout(r, ms));
const $ = (id) => document.getElementById(id);
const pruefungen = [];
const pruefe = (name, ok, detail) => pruefungen.push({ name, ok: Boolean(ok), detail: detail === undefined ? "" : String(detail) });
const code = () => $("ablaufStatus").dataset.code;
const zip = () => !$("btnDownloadZip").disabled;
async function dateien(liste) {
  const info = $("fileCountInfo");
  info.textContent = "";
  const dt = new DataTransfer();
  for (const [name, inhalt] of liste) dt.items.add(new File([inhalt], name, { type: "text/plain" }));
  const inp = $("inputFiles");
  inp.files = dt.files;
  inp.dispatchEvent(new Event("change"));
  await bis(() => /bereit/.test(info.textContent));
}
async function lauf() {
  const banner = $("auditBanner");
  banner.textContent = "";
  $("btnRunAnon").click();
  await bis(() => /Prüfergebnis/.test(banner.textContent));
  await warte(50);
}
function anonText() { return Array.from(document.querySelectorAll("#previewAnon .vz-text")).map(t => t.textContent).join("\\n"); }
const EINGABE = "ntp server 192.0.2.10\\nip address 172.22.0.230 255.255.255.0\\n";
window.addEventListener("load", async () => {
  try {
    pruefe("IP: Schlüsselmodus ist Standard", $("optIpModusSchluessel") && $("optIpModusSchluessel").checked && !$("optIpModusPlatzhalter").checked);
    pruefe("IP: Standardeinstellungen aktiv", /Standardeinstellungen aktiv/.test($("einstellungsZusammenfassung").textContent), $("einstellungsZusammenfassung").textContent);
    pruefe("IP: Hinweis ohne geladenen Schlüssel", /Kein IP-Schlüssel/.test($("ipKeyStatus").textContent), $("ipKeyStatus").textContent);
    await dateien([["a.txt", EINGABE]]);
    await lauf();
    const t1 = anonText();
    pruefe("IP: Adressen verfremdet, Maske bleibt, keine Platzhalter", !/192\\.0\\.2\\.10(?![0-9])/.test(t1) && !/172\\.22\\.0\\.230/.test(t1) && /ip address 172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]+\\.230 255\\.255\\.255\\.0/.test(t1) && !/NET-/.test(t1), t1);
    pruefe("IP: neuer Schlüssel mit Kennung und Hinweis 'andere Abbildung'", /Kennung [0-9a-f]{16}/.test($("ipKeyStatus").textContent) && /anders abgebildet/.test($("ipKeyStatus").textContent), $("ipKeyStatus").textContent);
    pruefe("IP: Hinweis 'schlüsselbasiert verfremdet, Netze rechnerisch korrekt' nach dem Lauf", !$("ipLaufHinweis").hidden && /schlüsselbasiert verfremdet, Netze rechnerisch korrekt/.test($("ipLaufHinweis").textContent), $("ipLaufHinweis").textContent);
    pruefe("IP: keine Restfunde, Freigabe möglich", code() === "KEINE_RESTFUNDE" && zip(), code());
    $("btnDownloadReport").click();
    await warte(50);
    const bericht = JSON.parse(await blobs[blobs.length - 1].text());
    pruefe("IP: Bericht mit Modus, Kennung und Hinweis", bericht.ipModus === "schluessel" && /^[0-9a-f]{16}$/.test(bericht.ipSchluesselKennung) && bericht.ipHinweis === "IP-Adressen sind schlüsselbasiert verfremdet, Netze rechnerisch korrekt.", JSON.stringify(bericht).slice(0, 300));
    $("ipKeyPass").value = "kurz";
    $("btnIpKeySpeichern").click();
    await bis(() => /12 Zeichen/.test($("ipKeyMeldung").textContent));
    pruefe("IP: zu kurzes Passwort beim Speichern abgelehnt", /12 Zeichen/.test($("ipKeyMeldung").textContent), $("ipKeyMeldung").textContent);
    $("ipKeyPass").value = "Testpasswort-IP-1";
    const nVor = namen.length;
    $("btnIpKeySpeichern").click();
    await bis(() => namen.length > nVor);
    const keyName = namen[namen.length - 1];
    const keyText = await blobs[blobs.length - 1].text();
    pruefe("IP: Schlüssel als .anonkey (ANON-AES256-2) gespeichert", /\\.anonkey$/.test(keyName) && JSON.parse(keyText).format === "ANON-AES256-2", keyName);
    pruefe("IP: Passwortfeld nach dem Speichern geleert", $("ipKeyPass").value === "");
    // Rückübersetzung nur über den Schlüssel (Zuordnung geleert)
    $("btnResetTableState").click();
    await warte(50);
    $("reverseInput").value = t1;
    $("btnRunDeanonymize").click();
    await bis(() => $("reverseOutput").value.length > 0);
    pruefe("IP: Rückübersetzung über den Schlüssel liefert die Original-IPs", $("reverseOutput").value.trim() === EINGABE.trim(), $("reverseOutput").value);
    pruefe("IP: Hinweis 'nur über den IP-Schlüssel' bei der Rückübersetzung", /nur über den IP-Schlüssel/.test($("reverseMeldung").textContent), $("reverseMeldung").textContent);
    // Neuer Schlüssel: Ergebnis veraltet, andere Abbildung
    const kennung1 = ($("ipKeyStatus").textContent.match(/Kennung ([0-9a-f]{16})/) || [])[1];
    $("btnIpKeyNeu").click();
    await bis(() => { const m = $("ipKeyStatus").textContent.match(/Kennung ([0-9a-f]{16})/); return m && m[1] !== kennung1; });
    pruefe("IP: neuer Schlüssel macht das Ergebnis veraltet", code() === "VERALTET" && !zip(), code());
    await lauf();
    pruefe("IP: neuer Schlüssel bildet anders ab", anonText() !== t1 && !/NET-/.test(anonText()), anonText());
    // Gespeicherten Schlüssel laden: wieder dieselbe Abbildung
    $("ipKeyPass").value = "Testpasswort-IP-1";
    const dt = new DataTransfer();
    dt.items.add(new File([keyText], keyName, { type: "application/json" }));
    $("inputIpKeyFile").files = dt.files;
    $("inputIpKeyFile").dispatchEvent(new Event("change"));
    await bis(() => /geladen/.test($("ipKeyStatus").textContent) || $("ipKeyMeldung").textContent.length > 0);
    pruefe("IP: .anonkey geladen (gleiche Kennung)", /geladen/.test($("ipKeyStatus").textContent) && $("ipKeyStatus").textContent.indexOf(kennung1) >= 0, $("ipKeyStatus").textContent + " " + $("ipKeyMeldung").textContent);
    await lauf();
    pruefe("IP: geladener Schlüssel bildet wie zuvor ab", anonText() === t1, anonText());
    let speicher = -1;
    try { speicher = localStorage.length + sessionStorage.length; } catch (e) { speicher = 0; }
    pruefe("IP: nichts im Browser-Speicher", speicher === 0, speicher);
    // Alter Modus bleibt wählbar
    $("optIpModusPlatzhalter").checked = true;
    $("optIpModusPlatzhalter").dispatchEvent(new Event("change", { bubbles: true }));
    await warte(50);
    pruefe("IP: alter Modus als Abweichung sichtbar", /alter Modus/.test($("einstellungsZusammenfassung").textContent), $("einstellungsZusammenfassung").textContent);
    await lauf();
    pruefe("IP: alter Modus NET-n.Hm wählbar", /NET-[0-9]+\\.H[0-9]+/.test(anonText()) && $("ipLaufHinweis").hidden, anonText());
  } catch (e) { window.__fehler.push("Probe: " + e.message); }
  const out = document.createElement("pre");
  out.id = "__probe";
  out.textContent = JSON.stringify({ fehler: window.__fehler, alerts: window.__alerts, pruefungen });
  document.body.appendChild(out);
});
</script></body>`;

// 5. Sammelentscheidungen für Fundgruppen (Schritt 3)
const PROBE_SAMMEL = `<script>
${WARTE_HILFE}
window.__fehler = [];
window.__alerts = 0;
window.addEventListener("error", e => window.__fehler.push(String(e.message)));
window.alert = () => { window.__alerts++; };
window.confirm = () => true;
const blobs = [];
const origUrl = URL.createObjectURL.bind(URL);
URL.createObjectURL = (b) => { blobs.push(b); return origUrl(b); };
const warte = (ms) => new Promise(r => setTimeout(r, ms));
const $ = (id) => document.getElementById(id);
const pruefungen = [];
const pruefe = (name, ok, detail) => pruefungen.push({ name, ok: Boolean(ok), detail: detail === undefined ? "" : String(detail) });
const code = () => $("ablaufStatus").dataset.code;
const zip = () => !$("btnDownloadZip").disabled;
async function dateien(liste) {
  const info = $("fileCountInfo");
  info.textContent = "";
  const dt = new DataTransfer();
  for (const [name, inhalt] of liste) dt.items.add(new File([inhalt], name, { type: "text/plain" }));
  const inp = $("inputFiles");
  inp.files = dt.files;
  inp.dispatchEvent(new Event("change"));
  await bis(() => /bereit/.test(info.textContent));
}
async function lauf(knopf) {
  const banner = $("auditBanner");
  banner.textContent = "";
  $(knopf || "btnRunAnon").click();
  await bis(() => /Prüfergebnis/.test(banner.textContent));
  await warte(50);
}
// erfundene Hexwerte (34 Zeichen, ohne Schlüsselwort): Verdachtsfunde
async function hexWert(i) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode("sammel-browser-" + i)));
  return Array.from(h).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 34);
}
const karten = () => Array.from(document.querySelectorAll(".fundkarte"));
const offen = () => karten().filter(k => !k.classList.contains("entschieden")).length;
const anzahl = () => $("sammelAnzahl").textContent;
window.addEventListener("load", async () => {
  try {
    const zeilen = [];
    for (let i = 0; i < 50; i++) zeilen.push("x " + await hexWert(i));
    await dateien([["v.log", zeilen.join("\\n") + "\\n"]]);
    await lauf();
    pruefe("Sammel: 50 offene Verdachtsfunde", code() === "OFFENE_FUNDE" && offen() === 50 && !$("sammelLeiste").hidden, code() + " " + offen());
    pruefe("Sammel: jede Fundkarte hat ein Auswahl-Häkchen", karten().every(k => k.querySelector("input.fk-auswahl")));
    $("btnSammelAlle").click(); await warte(20);
    pruefe("Sammel: 'Alle auswählen' zeigt 50 ausgewählt", /^50 ausgewählt/.test(anzahl()), anzahl());
    $("btnSammelFreigeben").click(); await warte(20);
    pruefe("Sammel: Freigabe ohne gemeinsame Bestätigung gesperrt", $("sammelZusammenfassung").hidden && /bestätigen/i.test($("sammelStatus").textContent) && offen() === 50, $("sammelStatus").textContent);
    pruefe("Sammel: EINE Bestätigung für alle Verdachtsfunde", !$("sammelBestaetigungZeile").hidden && /Ich habe die 50 ausgewählten Verdachtsfunde geprüft: kein Geheimnis/.test($("sammelBestaetigungText").textContent), $("sammelBestaetigungText").textContent);
    $("sammelBestaetigung").click(); await warte(20);
    $("btnSammelFreigeben").click(); await warte(20);
    pruefe("Sammel: Zusammenfassung vor dem Anwenden (Kategorie, Aktion, Anzahl)", !$("sammelZusammenfassung").hidden && /50/.test($("sammelZusammenfassungText").textContent) && $("sammelZusammenfassungListe").children.length === 50 && offen() === 50, $("sammelZusammenfassungText").textContent);
    $("btnSammelBestaetigen").click(); await warte(50);
    pruefe("Sammel: 50 Verdachtsfunde mit einem Klick freigegeben", offen() === 0, offen());
    $("btnSammelRueckgaengig").click(); await warte(50);
    pruefe("Sammel: Rückgängig stellt den Zustand wieder her", offen() === 50 && $("btnSammelRueckgaengig").disabled, offen());
    $("btnSammelAlle").click(); await warte(20);
    if (!$("sammelBestaetigung").checked) $("sammelBestaetigung").click();
    $("btnSammelFreigeben").click(); await warte(20);
    $("btnSammelBestaetigen").click(); await warte(50);
    const einzel = karten()[0].querySelector('button[data-aktion="rueckgaengig"]');
    einzel.click(); await warte(50);
    pruefe("Sammel: Einzelkarte bleibt einzeln änderbar", offen() === 1, offen());
    const k0 = karten().find(k => !k.classList.contains("entschieden"));
    const bes = k0.querySelector("input[data-bestaetigung]"); bes.click(); await warte(20);
    k0.querySelector('button[data-aktion="unveraendert"]').click(); await warte(50);
    await lauf("btnApplyFindingDecisions");
    pruefe("Sammel: nach dem Anwenden keine Restfunde, Download frei", code() === "KEINE_RESTFUNDE" && zip(), code());
    pruefe("Sammel: Zähler 'davon per Sammelaktion: 49'", /50 bewusst freigegeben, davon per Sammelaktion: 49/.test($("ablaufStatus").textContent), $("ablaufStatus").textContent);
    $("btnDownloadReport").click(); await warte(50);
    const bericht = JSON.parse(await blobs[blobs.length - 1].text());
    pruefe("Sammel: Bericht weist Sammelfreigaben getrennt aus", bericht.bewusstFreigegeben === 50 && bericht.bewusstFreigegebenSammelaktion === 49, JSON.stringify([bericht.bewusstFreigegeben, bericht.bewusstFreigegebenSammelaktion]));
    // 3 Verdacht + 1 sicheres Geheimnis: Geheimnis wird übersprungen und bleibt offen
    $("btnClearAll").click(); await warte(50);
    await dateien([["g.log", ["x " + await hexWert(100), "x " + await hexWert(101), "x " + await hexWert(102), "authorization Kx7mPq2zQ", ""].join("\\n")]]);
    await lauf();
    pruefe("Sammel: 4 offene Fundgruppen", offen() === 4, offen());
    $("btnSammelAlle").click(); await warte(20);
    pruefe("Sammel: Bestätigung nennt nur die 3 Verdachtsfunde", /Ich habe die 3 ausgewählten Verdachtsfunde/.test($("sammelBestaetigungText").textContent), $("sammelBestaetigungText").textContent);
    $("sammelBestaetigung").click(); await warte(20);
    $("btnSammelFreigeben").click(); await warte(20);
    $("btnSammelBestaetigen").click(); await warte(50);
    const offeneKarte = karten().find(k => !k.classList.contains("entschieden"));
    pruefe("Sammel: sicheres Geheimnis übersprungen und weiter offen", offen() === 1 && offeneKarte && /sicher erkannt/.test(offeneKarte.textContent) && /1 übersprungen, weil sicheres Geheimnis/.test($("sammelStatus").textContent), $("sammelStatus").textContent);
    // Auswahl nach Kategorie, Tastatur, Umschalt+Klick
    $("btnSammelRueckgaengig").click(); await warte(50);
    $("btnSammelKeine").click(); await warte(20);
    pruefe("Sammel: 'Auswahl aufheben'", /^0 ausgewählt/.test(anzahl()), anzahl());
    const opt = Array.from($("sammelKategorie").options).find(o => /Verdacht/.test(o.textContent));
    $("sammelKategorie").value = opt ? opt.value : "";
    $("btnSammelKategorie").click(); await warte(20);
    pruefe("Sammel: Auswahl nach Kategorie (alle Verdacht)", /^3 ausgewählt/.test(anzahl()), anzahl());
    $("btnSammelKeine").click(); await warte(20);
    $("sammelDatei").value = "g.log"; $("btnSammelDatei").click(); await warte(20);
    pruefe("Sammel: Auswahl nach Datei", /^4 ausgewählt/.test(anzahl()), anzahl());
    $("btnSammelKeine").click(); await warte(20);
    const k1 = karten()[1];
    k1.focus();
    k1.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    await warte(20);
    pruefe("Sammel: Leertaste markiert die fokussierte Karte", /^1 ausgewählt/.test(anzahl()) && karten()[1].querySelector("input.fk-auswahl").checked, anzahl());
    $("btnSammelKeine").click(); await warte(20);
    karten()[0].querySelector("input.fk-auswahl").click(); await warte(20);
    karten()[3].querySelector("input.fk-auswahl").dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, shiftKey: true }));
    await warte(20);
    pruefe("Sammel: Umschalt+Klick markiert einen Bereich", /^4 ausgewählt/.test(anzahl()), anzahl());
    // Dauerhafte Regel landet kategoriegebunden in ausnahmen.freigegeben
    if (!$("sammelBestaetigung").checked) $("sammelBestaetigung").click();
    document.querySelector('input[name="sammelUmfang"][value="dauerhaft"]').click();
    $("btnSammelFreigeben").click(); await warte(20);
    $("btnSammelBestaetigen").click(); await warte(50);
    pruefe("Sammel: dauerhafte Regel als 3 bewusst freigegebene Werte in den Einstellungen", /3 bewusst freigegebene Werte/.test($("einstellungsZusammenfassung").textContent), $("einstellungsZusammenfassung").textContent);
  } catch (e) { window.__fehler.push("Probe: " + e.message); }
  const out = document.createElement("pre");
  out.id = "__probe";
  out.textContent = JSON.stringify({ fehler: window.__fehler, alerts: window.__alerts, pruefungen });
  document.body.appendChild(out);
});
</script></body>`;

let passed = 0;
let failed = 0;
function assert(cond, msg) {
  if (cond) passed++;
  else { failed++; console.error("  [FEHLER] " + msg); }
}

const browser = findeBrowser();
if (!browser) {
  console.log("NICHT AUSGEFÜHRT: kein Chrome/Chromium gefunden (CHROME_PATH setzen).");
  process.exit(process.env.BROWSER_PFLICHT === "1" ? 1 : 0);
}

// Führt ein Testskript in einer Kopie der Seite aus und liefert das Ergebnisobjekt (oder null)
function probeAusfuehren(skript, budgetMs) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "anon-browser-"));
  try {
    const seite = path.join(tmp, "seite.html");
    fs.writeFileSync(seite, fs.readFileSync(HTML_PATH, "utf8").replace("</body>", skript), "utf8");
    const r = spawnSync(browser, ["--headless=new", "--disable-gpu", "--no-first-run", "--no-sandbox",
      `--user-data-dir=${path.join(tmp, "profil")}`, `--virtual-time-budget=${budgetMs || 60000}`, "--dump-dom",
      "file://" + seite.replace(/\\/g, "/")], { encoding: "utf8", timeout: 300000, maxBuffer: 64 * 1024 * 1024 });
    const m = /<pre id="__probe">([\s\S]*?)<\/pre>/.exec(r.stdout || "");
    if (!m) return null;
    return JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// 1. Exportfreigabe: jede relevante Änderung macht das Ergebnis ungültig
{
  const daten = probeAusfuehren(PROBE, 60000);
  assert(Boolean(daten), "Browser-Test: Ergebnis des Testskripts gefunden");
  if (daten) {
    assert(daten.fehler.length === 0, `Browser-Test: keine JavaScript-Fehler (${daten.fehler.join(" | ")})`);
    for (const st of daten.schritte) {
      const erwartet = st.name === "lauf";
      assert(st.zip === erwartet && st.kopie === erwartet,
        `Exportfreigabe nach '${st.name}': ZIP=${st.zip}, Kopieren=${st.kopie} (erwartet ${erwartet})`);
    }
    assert(daten.schritte.length === 13, `Browser-Test: alle 13 Schritte ausgeführt (${daten.schritte.length})`);
  }
}

// 2. Abnahmeaufgaben der Bedienoberfläche (a, b, c) und Zustandswechsel
{
  const daten = probeAusfuehren(PROBE_ABLAUF, 180000);
  assert(Boolean(daten), "Ablauf-Test: Ergebnis des Testskripts gefunden");
  if (daten) {
    assert(daten.fehler.length === 0, `Ablauf-Test: keine JavaScript-Fehler (${daten.fehler.join(" | ")})`);
    assert(daten.alerts === 0, `Ablauf-Test: keine alert()-Dialoge (${daten.alerts})`);
    for (const c of daten.pruefungen) assert(c.ok, `${c.name}${c.detail ? " (" + c.detail + ")" : ""}`);
    assert(daten.pruefungen.length >= 40, `Ablauf-Test: alle Prüfungen ausgeführt (${daten.pruefungen.length})`);
  }
}

// 3. Korrekturen nach Praxistest
{
  const daten = probeAusfuehren(PROBE_KORREKTUR, 120000);
  assert(Boolean(daten), "Korrektur-Test: Ergebnis des Testskripts gefunden");
  if (daten) {
    assert(daten.fehler.length === 0, `Korrektur-Test: keine JavaScript-Fehler (${daten.fehler.join(" | ")})`);
    assert(daten.alerts === 0, `Korrektur-Test: keine alert()-Dialoge (${daten.alerts})`);
    for (const c of daten.pruefungen) assert(c.ok, `${c.name}${c.detail ? " (" + c.detail + ")" : ""}`);
    assert(daten.pruefungen.length >= 28, `Korrektur-Test: alle Prüfungen ausgeführt (${daten.pruefungen.length})`);
  }
}

// 4. IP-Modell in der Oberfläche
{
  const daten = probeAusfuehren(PROBE_IPMODELL, 120000);
  assert(Boolean(daten), "IP-Modell-Test: Ergebnis des Testskripts gefunden");
  if (daten) {
    assert(daten.fehler.length === 0, `IP-Modell-Test: keine JavaScript-Fehler (${daten.fehler.join(" | ")})`);
    assert(daten.alerts === 0, `IP-Modell-Test: keine alert()-Dialoge (${daten.alerts})`);
    for (const c of daten.pruefungen) assert(c.ok, `${c.name}${c.detail ? " (" + c.detail + ")" : ""}`);
    assert(daten.pruefungen.length >= 20, `IP-Modell-Test: alle Prüfungen ausgeführt (${daten.pruefungen.length})`);
  }
}

// 5. Sammelentscheidungen für Fundgruppen
{
  const daten = probeAusfuehren(PROBE_SAMMEL, 180000);
  assert(Boolean(daten), "Sammel-Test: Ergebnis des Testskripts gefunden");
  if (daten) {
    assert(daten.fehler.length === 0, `Sammel-Test: keine JavaScript-Fehler (${daten.fehler.join(" | ")})`);
    assert(daten.alerts === 0, `Sammel-Test: keine alert()-Dialoge (${daten.alerts})`);
    for (const c of daten.pruefungen) assert(c.ok, `${c.name}${c.detail ? " (" + c.detail + ")" : ""}`);
    assert(daten.pruefungen.length >= 21, `Sammel-Test: alle Prüfungen ausgeführt (${daten.pruefungen.length})`);
  }
}

console.log(`\n========================================`);
console.log(`TESTERGEBNIS (Browser, ${path.basename(browser)}): ${passed} bestanden, ${failed} fehlgeschlagen`);
console.log(`========================================`);
process.exit(failed > 0 ? 1 : 0);
