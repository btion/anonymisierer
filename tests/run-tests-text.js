// Testskript (Node.js) für web/text/text-anonymisierer.html und core/text/text-engine.js
// (Freitext-Pseudonymisierung, Mechanismus pro Kategorie, gemeinsames Tabellenformat)

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..");
const HTML_PATH = path.join(ROOT, "web", "text", "text-anonymisierer.html");

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error("  [FEHLER] " + msg);
  }
}

const htmlContent = fs.readFileSync(HTML_PATH, "utf8");
const scriptMatch = htmlContent.match(/<script id="anon-text-script">([\s\S]*?)<\/script>/);
assert(Boolean(scriptMatch), "Skriptblock in text-anonymisierer.html gefunden");
const sandbox = {
  module: { exports: {} },
  exports: {},
  TextEncoder,
  TextDecoder,
  Uint8Array,
  DataView,
  ArrayBuffer,
  crypto: crypto.webcrypto,
  atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
  btoa: (bin) => Buffer.from(bin, "binary").toString("base64"),
  console
};
vm.runInNewContext(scriptMatch[1], sandbox, { filename: "text-anonymisierer.html" });
const core = sandbox.module.exports;

(async () => {
  console.log("=== 1. Prüfe Text-Pseudonymisierungs-Engine (core/text) ===");
  const textEnginePath = path.join(ROOT, "core", "text", "text-engine.js");
  assert(fs.existsSync(textEnginePath), "core/text/text-engine.js existiert");

  const textCore = require(textEnginePath);
  const textEngineSource = fs.readFileSync(textEnginePath, "utf8");

  // Pflichtkommentare mit Quellenangaben
  assert(textEngineSource.includes("Quelle: ISO 7064, MOD 97-10"), "IBAN-Quelle im Code dokumentiert");
  assert(textEngineSource.includes("Quelle: § 139b AO, DIN ISO 7064 Mod 11, 10"), "Steuer-ID Quelle im Code dokumentiert");
  assert(textEngineSource.includes("Quelle: § 290 SGB V / GKV-Spitzenverband"), "KVNR-Quelle im Code dokumentiert");
  assert(textEngineSource.includes("Quelle: § 147 SGB VI"), "RVNR-Quelle im Code dokumentiert");
  assert(textEngineSource.includes("Quelle: KBV-Richtlinie"), "LANR-Quelle im Code dokumentiert");
  assert(textEngineSource.includes("Quelle: ICAO Doc 9303 / Personalausweisgesetz"), "Personalausweis-Quelle im Code dokumentiert");
  assert(textEngineSource.includes("Quelle: ISO 9362"), "BIC-Quelle im Code dokumentiert");

  // Prüfziffern-Tests (Positiv)
  assert(textCore.isValidIban("DE89 3704 0044 0532 0130 00"), "Gültige Test-IBAN wird als valide erkannt");
  assert(textCore.isValidSteuerId("86095742719"), "Gültige Test-Steuer-ID wird als valide erkannt");
  assert(textCore.isValidKvnr("A123456780"), "Gültige Test-KVNR wird als valide erkannt");
  assert(textCore.isValidRvnr("12150785M041"), "Gültige Test-RVNR wird als valide erkannt");
  assert(textCore.isValidLanr("123456601"), "Gültige Test-LANR wird als valide erkannt");
  assert(textCore.isValidPersonalausweis("T220001293"), "Gültiger Test-Personalausweis wird als valide erkannt");
  assert(textCore.isValidBic("GENODEF1M01"), "Gültiger Test-BIC wird als valide erkannt");

  // Prüfziffern-Tests (Negativ / Grenzfälle)
  assert(!textCore.isValidIban("DE89 3704 0044 0532 0130 99"), "Ungültige IBAN (Zahlendreher) wird abgewiesen");
  assert(!textCore.isValidSteuerId("11111111111"), "Ungültige Steuer-ID (ungültige Häufigkeit) wird abgewiesen");
  assert(!textCore.isValidKvnr("Z999999999"), "Ungültige KVNR wird abgewiesen");
  assert(!textCore.isValidRvnr("12150785M049"), "Ungültige RVNR (falsche Prüfziffer) wird abgewiesen");
  assert(!textCore.isValidLanr("123456701"), "Ungültige LANR (falsche Prüfziffer) wird abgewiesen");
  assert(!textCore.isValidBic("XXXX99XX"), "Ungültiger BIC (ungültiger Ländercode) wird abgewiesen");

  // Testfälle aus tests/faelle-text.json
  const textFaellePath = path.join(__dirname, "faelle-text.json");
  assert(fs.existsSync(textFaellePath), "tests/faelle-text.json existiert");
  const textFaelle = JSON.parse(fs.readFileSync(textFaellePath, "utf8")).faelle;

  for (const fall of textFaelle) {
    const spans = textCore.analyzeText(fall.text);

    // Erwartete ROT-Kategorien
    if (fall.erwarteRotKategorien) {
      for (const cat of fall.erwarteRotKategorien) {
        const found = spans.some(s => s.tier === "ROT" && s.category === cat);
        assert(found, `Fall '${fall.id}': Erwartete ROT-Kategorie '${cat}' gefunden`);
      }
    }

    // Erwartete GELB-Kategorien
    if (fall.erwarteGelbKategorien) {
      for (const cat of fall.erwarteGelbKategorien) {
        const found = spans.some(s => s.tier === "GELB" && s.category === cat);
        assert(found, `Fall '${fall.id}': Erwartete GELB-Kategorie '${cat}' gefunden`);
      }
    }

    // Negativ-Prüfungen: darf nicht ROT sein
    if (fall.darfNichtRotSein) {
      for (const invalidItem of fall.darfNichtRotSein) {
        const foundInRed = spans.some(s => s.tier === "ROT" && s.text.includes(invalidItem));
        assert(!foundInRed, `Fall '${fall.id}': Ungültiger Wert '${invalidItem}' wird NIEMALS als ROT erkannt`);
      }
    }

    // Negativ-Prüfungen: Netzwerk-Muster dürfen nicht fehlklassifiziert werden
    if (fall.darfNichtKategorieSein) {
      for (const [targetStr, forbiddenCats] of Object.entries(fall.darfNichtKategorieSein)) {
        for (const span of spans) {
          if (span.text.includes(targetStr)) {
            for (const fCat of forbiddenCats) {
              assert(span.category !== fCat, `Fall '${fall.id}': '${targetStr}' darf nicht Kategorie '${fCat}' sein (war: '${span.category}')`);
            }
          }
        }
      }
    }

    // ICD/OPS Schutzprüfung
    if (fall.erhalteUnveraendert) {
      for (const item of fall.erhalteUnveraendert) {
        const spanCovers = spans.some(s => s.text.includes(item));
        assert(!spanCovers, `Fall '${fall.id}': Fachbegriff '${item}' bleibt unberührt`);
      }
    }

    // Teste Pseudonymisierung im Token-Modus
    // Aktiviere alle ROT-Spans für die Ausführung
    const resultToken = textCore.pseudonymizeText(fall.text, spans, { mode: "token" });
    assert(
      resultToken.status.startsWith("Geprüft, ") && resultToken.status.endsWith(" Treffer ersetzt, Sichtprüfung erforderlich"),
      `Fall '${fall.id}': Status lautet 'Geprüft, n Treffer ersetzt, Sichtprüfung erforderlich' (kein 'SAUBER')`
    );
    assert(!resultToken.status.includes("SAUBER"), `Fall '${fall.id}': Kein SAUBER-Urteil im Text-Modus`);
    assert(resultToken.notice.includes("Rückführbar über die Zuordnungstabelle"), `Fall '${fall.id}': Rechtlicher Hinweistext vorhanden`);

    // Teste Pseudonymisierung im Schwärzungs-Modus
    const resultRedact = textCore.pseudonymizeText(fall.text, spans, { mode: "redaction" });
    if (spans.some(s => s.active)) {
      assert(resultRedact.text.includes("█"), `Fall '${fall.id}': Schwärzungsmodus enthält Schwärzungszeichen '█'`);
    }

    // XSS-Prüfung
    if (fall.id === "xss_sicherheit") {
      assert(resultToken.text.includes("<script>"), "HTML-Tags im Text werden nicht unerwünscht modifiziert");
    }

    // Spezifischer Test für Datumsverschiebung pro Fall
    if (fall.testVerschiebungTage) {
      // Aktiviere alle Datums-Spans für diesen Test
      for (const s of spans) {
        if (s.category === "DATUM" || s.category === "GEBURTSDATUM") s.active = true;
      }
      const resultShift = textCore.pseudonymizeText(fall.text, spans, {
        shiftDates: true,
        dateShiftDays: fall.testVerschiebungTage
      });

      for (const expDate of fall.erwarteVerschobeneDaten) {
        assert(resultShift.text.includes(expDate), `Fall '${fall.id}': Erwartetes verschobenes Datum '${expDate}' im Text vorhanden`);
      }
      // WICHTIG: Versatz darf NIEMALS im Ausgabetext vorkommen!
      assert(
        !resultShift.text.includes(fall.testVerschiebungTage + " Tage") &&
        !resultShift.text.includes("Versatz") &&
        !resultShift.text.includes("+" + fall.testVerschiebungTage),
        `Fall '${fall.id}': Versatzangabe steht NICHT in der Textausgabe`
      );
      // Versatz ist jedoch in den Mapping-Metadaten für die Tabelle vorhanden
      const hasMeta = resultShift.mapping.some(m => m.meta && m.meta.dateShiftDays === fall.testVerschiebungTage);
      assert(hasMeta, `Fall '${fall.id}': Versatzangabe in den Zuordnungs-Metadaten für die Tabelle vorhanden`);
    }
  }

  // Eingebettete Kopien entsprechen core/ (gemeinsamer Kern)
  const nichtSynchron = require(path.join(ROOT, "tools", "einbetten.js")).pruefen();
  assert(nichtSynchron.length === 0, `Freitext-Engine: Kopie in text-anonymisierer.html identisch mit core/text/text-engine.js (${nichtSynchron.join(", ") || "ok"})`);
  assert(htmlContent.includes("// >>> core/text/text-engine.js") && htmlContent.includes("// >>> core/tabelle/zuordnung.js") && htmlContent.includes("// >>> core/tabelle/krypto.js"), "text-anonymisierer.html bettet text-engine, zuordnung und krypto ein");

  // 18.y Mechanismus pro Kategorie (platzhalter | entfernen | generalisieren)
  {
    const mText = "Geb. 12.03.1987, wohnhaft Musterweg 12a, 12345 Musterstadt, Tel. 030 1234567, Mail max@beispiel.example, IP 192.0.2.44, Herr Hans Beispiel";
    const spanOf = (needle, category) => {
      const i = mText.indexOf(needle);
      return { start: i, end: i + needle.length, category, active: true, text: needle };
    };
    const mSpans = [
      spanOf("12.03.1987", "GEBURTSDATUM"),
      spanOf("Musterweg 12a", "STRASSE_NR"),
      spanOf("12345 Musterstadt", "PLZ_ORT"),
      spanOf("030 1234567", "TELEFON"),
      spanOf("max@beispiel.example", "EMAIL"),
      spanOf("192.0.2.44", "IP"),
      spanOf("Hans Beispiel", "NAME")
    ];
    const allGen = {};
    for (const s of mSpans) allGen[s.category] = "generalisieren";
    const gen = textCore.pseudonymizeText(mText, mSpans, { mechanismen: allGen });
    assert(gen.text === "Geb. 1987, wohnhaft Musterweg, 12xxx, Tel. 030 …, Mail …@beispiel.example, IP 192.0.2.x, Herr [NAME-1]",
      `Mechanismus generalisieren: Werte vergröbert, NAME ohne Regel fällt auf Platzhalter zurück (${gen.text})`);
    assert(gen.mapping.length === 1 && gen.mapping[0].placeholder === "[NAME-1]", "Mechanismus generalisieren: nur Platzhalter landen in der Zuordnungstabelle");
    assert(gen.mechanismusZaehler.generalisieren === 6 && gen.mechanismusZaehler.platzhalter === 1, "Mechanismus generalisieren: Zähler je Mechanismus stimmen");

    const mixed = textCore.pseudonymizeText(mText, mSpans, { mode: "token", mechanismen: { EMAIL: "entfernen", GEBURTSDATUM: "generalisieren" } });
    assert(mixed.text.includes("Geb. 1987,") && mixed.text.includes("Mail " + "█".repeat(20) + ",") && mixed.text.includes("[NAME-1]") && mixed.text.includes("[IP-1]"),
      `Mechanismus gemischt: pro Kategorie unterschiedlich, Rest nach Modus (${mixed.text})`);
    const redactDefault = textCore.pseudonymizeText(mText, mSpans, { mode: "redaction", mechanismen: { NAME: "platzhalter" } });
    assert(redactDefault.text.includes("[NAME-1]") && !redactDefault.text.includes("[IP-"), "Mechanismus: Modus Schwärzung als Vorgabe, Ausnahme pro Kategorie möglich");
    assert(textCore.generalisiereWert("NAME", "Hans") === null && textCore.generalisiereWert("PLZ_ORT", "Musterstadt") === null, "generalisiereWert: ohne Regel bzw. ohne passenden Wert null");
    assert(JSON.stringify(textCore.MECHANISMEN) === JSON.stringify(["platzhalter", "entfernen", "generalisieren"]), "Mechanismen: platzhalter, entfernen, generalisieren");

    // Fortlaufende Nummerierung über mehrere Texte und Übernahme in die Zuordnungstabelle
    const tState = new core.AnonState();
    const t1 = "Herr Hans Beispiel";
    const r1 = textCore.pseudonymizeText(t1, [{ start: 5, end: 18, category: "NAME", active: true }], { bekannt: core.collectKnownTextTokens(tState) });
    core.registerTextMappingInState(tState, r1.mapping);
    const t2 = "Frau Erika Beispiel und Herr Hans Beispiel";
    const r2 = textCore.pseudonymizeText(t2, [
      { start: 5, end: 19, category: "NAME", active: true },
      { start: 29, end: 42, category: "NAME", active: true }
    ], { bekannt: core.collectKnownTextTokens(tState) });
    core.registerTextMappingInState(tState, r2.mapping);
    assert(r1.text === "Herr [NAME-1]" && r2.text === "Frau [NAME-2] und Herr [NAME-1]",
      `Text-Reiter: Nummerierung bleibt über mehrere Texte eindeutig (${r2.text})`);
    assert(core.deanonymizeText("[NAME-2] schreibt an [NAME-1]", tState) === "Erika Beispiel schreibt an Hans Beispiel",
      "Text-Reiter: Platzhalter aus der Zuordnungstabelle werden zurückübersetzt");
    const execHandler = htmlContent.slice(htmlContent.indexOf('getElementById("btnTextExecute")'), htmlContent.indexOf("// ICD/OPS Schutzprüfung") > 0 ? htmlContent.indexOf("// ICD/OPS Schutzprüfung") : htmlContent.length);
    assert(!htmlContent.includes("currentState.reverseMap") && !htmlContent.includes("currentState.categories"), "Text-Reiter: keine Zugriffe auf nicht vorhandene Felder reverseMap/categories");
    assert(execHandler.includes("registerTextMappingInState(") && execHandler.includes("readTextMechanismenFromUI()"), "Text-Reiter: Übernahme nutzt registerTextMappingInState und Mechanismen aus der Oberfläche");
  }

  // Mathematische Schaltjahr-Tests für shiftDate
  assert(textCore.shiftDate("28.02.2024", 1) === "29.02.2024", "shiftDate: Schaltjahr 2024 korrekt behandelt (28.02. -> 29.02.)");
  assert(textCore.shiftDate("28.02.2023", 1) === "01.03.2023", "shiftDate: Kein Schaltjahr 2023 korrekt behandelt (28.02. -> 01.03.)");
  assert(textCore.shiftDate("2024-02-28", 1) === "2024-02-29", "shiftDate: ISO-Format YYYY-MM-DD korrekt verschoben");

  // UI-Hinweise in der Seite und im README
  const readmeContent = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  assert(htmlContent.includes("Text-Reiter nur Web, in anon.ps1 nicht enthalten"), "Hinweis 'nur Web, in anon.ps1 nicht enthalten' in text-anonymisierer.html vorhanden");
  assert(/nur Web,\s*in\s*(`?anon\.ps1`?)\s*nicht enthalten/i.test(readmeContent), "Hinweis 'nur Web, in anon.ps1 nicht enthalten' im README.md vorhanden");
  assert(htmlContent.includes("Rückführbar über die Zuordnungstabelle. Ersetzt keine fachliche Sichtprüfung"), "Rechtlicher Hinweistext in text-anonymisierer.html vorhanden");
  assert(htmlContent.includes("id=\"tab-text\"") && htmlContent.includes("textInteractivePreview"), "Text-Bereich mit interaktiver Vorschau vorhanden");
  assert(htmlContent.includes("default-src 'none'") && htmlContent.includes("connect-src 'none'") && !/<script[^>]+src=/i.test(htmlContent), "text-anonymisierer.html: CSP ohne Netz, keine externen Skripte");
  assert(!/localStorage|sessionStorage|indexedDB/.test(htmlContent), "text-anonymisierer.html: kein localStorage/sessionStorage/indexedDB");
  const exportHandlerText = htmlContent.slice(htmlContent.indexOf('getElementById("btnExportEncryptedTable")'), htmlContent.indexOf('getElementById("btnLoadTableFile")'));
  assert(exportHandlerText.includes("encryptTableAes256V2(") && exportHandlerText.includes('getElementById("tableSavePass").value = ""'), "text-anonymisierer.html: Tabelle als ANON-AES256-2, Passwortfelder werden geleert");

  // XSS-Sicherheitstest für DOM-Erzeugung
  // Simulieren wir die DOM-Generierung: Spans und Text-Segmente werden als DOM-Knoten erzeugt
  const maliciousInput = "<script>alert('pwn')</script><img src=x onerror=alert(1)> test@domain.example.net";
  const malSpans = textCore.analyzeText(maliciousInput);
  assert(malSpans.length > 0, "E-Mail in XSS-Text wird erkannt");
  // Überprüfe, dass bei reiner Textknoten-Verwendung keine Tags interpretiert werden
  let simulatedDomText = "";
  let lastMIdx = 0;
  for (const s of malSpans) {
    simulatedDomText += maliciousInput.slice(lastMIdx, s.start);
    simulatedDomText += `[SPAN:${s.text}]`;
    lastMIdx = s.end;
  }
  simulatedDomText += maliciousInput.slice(lastMIdx);
  assert(simulatedDomText.includes("<script>alert('pwn')</script>"), "Original-Code bleibt unverändert im Textknoten");
  assert(simulatedDomText.includes("[SPAN:test@domain.example.net]"), "Span umfasst sicher das Token");

  // Gemeinsames Tabellenformat: Text-Platzhalter überstehen Verschlüsselung und Laden (ANON-AES256-2)
  {
    const st = new core.AnonState();
    const r = textCore.pseudonymizeText("Herr Hans Beispiel", [{ start: 5, end: 18, category: "NAME", active: true }], { bekannt: core.collectKnownTextTokens(st) });
    core.registerTextMappingInState(st, r.mapping);
    const enc = await core.encryptTableAes256V2(JSON.stringify(st.toJSON()), "TextTabelle#2026!", 1000);
    assert(JSON.parse(enc).format === "ANON-AES256-2", "Text-Tabelle wird als ANON-AES256-2 gespeichert");
    const loaded = core.AnonState.fromJSON(await core.decryptTableWebCrypto(enc, "TextTabelle#2026!"));
    assert(core.deanonymizeText("Antwort an [NAME-1]", loaded) === "Antwort an Hans Beispiel", "Text-Tabelle: nach Laden wird [NAME-1] zurückübersetzt");
    const next = textCore.pseudonymizeText("Frau Erika Beispiel", [{ start: 5, end: 19, category: "NAME", active: true }], { bekannt: core.collectKnownTextTokens(loaded) });
    assert(next.text === "Frau [NAME-2]", "Text-Tabelle: Nummerierung läuft nach dem Laden weiter");
  }

  console.log(`\n========================================`);
  console.log(`TESTERGEBNIS (Text, Node.js): ${passed} bestanden, ${failed} fehlgeschlagen`);
  console.log(`========================================`);
  process.exit(failed > 0 ? 1 : 0);
})();
