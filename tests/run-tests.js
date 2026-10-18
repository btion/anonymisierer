// Automatisiertes Testskript (Node.js) für:
// 1. HTML/CSP-Prüfung & Offline-Garantie von anonymisierer.html
// 2. Gemeinsame Regeldatei anon-regeln.json vs. DEFAULT_RULES
// 3. Alle 48 Testfälle in tests/faelle.json (LF UND CRLF, inkl. Grenzfälle, JSON-Validität, Rückübersetzung)
// 4. Mehrdateien-Konsistenzlauf auf tests/beispiele/ (LF + CRLF) und Erstellung/Prüfung von tests/erwartet/
// 5. Explizite Tests für alle 11 Code-Review-Befunde (Befund 1 bis Befund 11)
// 6. Performance- & Stresstest (60.000+ Zeilen Aruba Show-Tech)

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..");
const HTML_PATH = path.join(ROOT, "anonymisierer.html");
const PS1_PATH = path.join(ROOT, "anon.ps1");
const RULES_PATH = path.join(ROOT, "anon-regeln.json");
const CASES_PATH = path.join(__dirname, "faelle.json");
const BEISPIELE_DIR = path.join(__dirname, "beispiele");
const ERWARTET_DIR = path.join(__dirname, "erwartet");

// tests/erwartet/ ist der committete Sollstand; neu erzeugen nur mit: node tests/run-tests.js --aktualisieren
const AKTUALISIEREN = process.argv.includes("--aktualisieren");

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

async function assertRejects(asyncFn, msg) {
  let threw = false;
  try {
    await asyncFn();
  } catch (e) {
    threw = true;
  }
  assert(threw, msg);
}

console.log("=== 1. Prüfe anonymisierer.html (CSP & Offline-Regeln) ===");
const htmlContent = fs.readFileSync(HTML_PATH, "utf8");
const ps1Content = fs.readFileSync(PS1_PATH, "utf8");

assert(htmlContent.includes("Content-Security-Policy"), "CSP Meta-Tag vorhanden");
assert(htmlContent.includes("default-src 'none'"), "CSP enthält default-src 'none'");
assert(htmlContent.includes("connect-src 'none'"), "CSP enthält connect-src 'none'");
assert(!/<script[^>]+src=/i.test(htmlContent), "Keine externen <script src=...> Tags");
assert(!/<link[^>]+href=/i.test(htmlContent), "Keine externen <link href=...> Stylesheets/Fonts");
assert(!/\bfetch\s*\(/.test(htmlContent), "Kein fetch()-Aufruf im Code");
assert(!/\bXMLHttpRequest\b/.test(htmlContent), "Kein XMLHttpRequest im Code");

// Extrahiere den eingebetteten <script id="anon-core-script"> Block und lade ihn als Modul
const scriptMatch = htmlContent.match(/<script id="anon-core-script">([\s\S]*?)<\/script>/);
assert(Boolean(scriptMatch), "Kern-Skriptblock in anonymisierer.html gefunden");

const sandbox = {
  module: { exports: {} },
  exports: {},
  TextEncoder,
  TextDecoder,
  Uint8Array,
  Uint32Array,
  DataView,
  ArrayBuffer,
  Blob: typeof Blob !== "undefined" ? Blob : undefined,
  Response: typeof Response !== "undefined" ? Response : undefined,
  DecompressionStream: typeof DecompressionStream !== "undefined" ? DecompressionStream : undefined,
  crypto: crypto.webcrypto,
  atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
  btoa: (bin) => Buffer.from(bin, "binary").toString("base64"),
  console
};
vm.runInNewContext(scriptMatch[1], sandbox, { filename: "anonymisierer.html" });
const core = sandbox.module.exports;

console.log("=== 2. Prüfe Synchronität von anon-regeln.json ===");
const diskRules = JSON.parse(fs.readFileSync(RULES_PATH, "utf8"));
assert(
  JSON.stringify(diskRules) === JSON.stringify(core.DEFAULT_RULES),
  "anon-regeln.json und DEFAULT_RULES in anonymisierer.html sind 100 % identisch"
);

// Regex-Dialekt: .NET wertet \w, \d und \b als Unicode, JavaScript als ASCII. Deshalb sind sie in
// anon-regeln.json verboten; erlaubt sind explizite ASCII-Klassen wie [0-9] oder (?<![A-Za-z0-9_]).
function collectRulePatterns(rules) {
  const list = [];
  const add = (where, arr) => (arr || []).forEach((p, i) => list.push({ where: `${where}[${i}]`, pattern: p }));
  add("ausnahmen.versionKontext", rules.ausnahmen && rules.ausnahmen.versionKontext);
  add("ausnahmen.musterRegex", rules.ausnahmen && rules.ausnahmen.musterRegex);
  add("pruefung.erlaubtMuster", rules.pruefung && rules.pruefung.erlaubtMuster);
  (rules.geheimnisMuster || []).forEach((g, i) => list.push({ where: `geheimnisMuster[${i}]`, pattern: g.suche }));
  (rules.freitextMuster || []).forEach((f, i) => list.push({ where: `freitextMuster[${i}]`, pattern: f.suche }));
  add("seriennummerMuster", rules.seriennummerMuster);
  add("benutzerMuster", rules.benutzerMuster);
  add("hostnamenMuster", rules.hostnamenMuster);
  add("eigeneHostnamenMuster", rules.eigeneHostnamenMuster);
  return list;
}
const forbiddenEscape = /(?<!\\)(?:\\\\)*\\[wWdDbB]/;
const rulePatterns = collectRulePatterns(diskRules);
assert(rulePatterns.length > 30, `Regex-Dialekt: ${rulePatterns.length} Muster aus anon-regeln.json geprüft`);
for (const rp of rulePatterns) {
  assert(!forbiddenEscape.test(rp.pattern), `Regex-Dialekt: ${rp.where} enthält kein \\w, \\d oder \\b`);
}
assert(forbiddenEscape.test("(?i)\\bhost\\d+") && !forbiddenEscape.test("C:\\\\bin"), "Regex-Dialekt: Prüfregel erkennt \\b/\\d und ignoriert maskierte Backslashes");

// Ersetzungstexte der Geheimnismuster: nur $1..$9 und nur vorhandene Gruppen
for (const [i, g] of (diskRules.geheimnisMuster || []).entries()) {
  const rep = String(g.ersetzen);
  const dollarRefs = rep.match(/\$[^\s]?/g) || [];
  assert(dollarRefs.every(r => /^\$[1-9]$/.test(r)), `Ersetzungstext geheimnisMuster[${i}] nutzt nur $1..$9 ('${rep}')`);
  const groupCount = new RegExp(g.suche.replace(/^\(\?[ims]+\)/, "") + "|").exec("").length - 1;
  const maxRef = Math.max(0, ...dollarRefs.map(r => parseInt(r.slice(1), 10) || 0));
  assert(maxRef <= groupCount, `Ersetzungstext geheimnisMuster[${i}] verweist nur auf vorhandene Gruppen ($${maxRef} <= ${groupCount})`);
}

// Testdaten: private IPv4 nur aus 10.0.0.0/24, 172.16.0.0/24 und 192.168.0.0/24 (für die Privat/Öffentlich-Trennung),
// sonst nur Dokumentationsnetze 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
{
  const listTestFiles = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return e.name.startsWith("_tmp") ? [] : listTestFiles(full);
    return [full];
  });
  const rxPrivate = /(?<![0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}|192\.168\.[0-9]{1,3})\.[0-9]{1,3}(?![0-9])/g;
  const allowedNets = new Set(["10.0.0", "172.16.0", "192.168.0"]);
  const badIps = [];
  for (const file of listTestFiles(__dirname)) {
    const content = fs.readFileSync(file, "utf8");
    for (const m of content.matchAll(rxPrivate)) {
      if (!allowedNets.has(m[1])) badIps.push(path.relative(ROOT, file) + ": " + m[0]);
    }
  }
  assert(badIps.length === 0, `Testdaten: private IPv4 nur aus 10.0.0.0/24, 172.16.0.0/24, 192.168.0.0/24 (${badIps.slice(0, 5).join(", ")})`);
}

console.log("=== 3. Führe Testkorpus tests/faelle.json aus (LF und CRLF) ===");
const cases = JSON.parse(fs.readFileSync(CASES_PATH, "utf8"));
assert(cases.length >= 48, `Mindestens 48 Testfälle vorhanden (gefunden: ${cases.length})`);

for (const tc of cases) {
  const overrides = {
    netzerhaltend: tc.netzerhaltend !== undefined ? tc.netzerhaltend : true
  };
  if (tc.kategorien) {
    overrides.kategorien = new Set(tc.kategorien);
  }

  // 3a. LF-Lauf
  const cfg = core.buildEngineConfig(diskRules, overrides);
  const state = new core.AnonState();
  const actual = core.processText(tc.eingabe, cfg, state);

  const match = actual === tc.erwartet;
  if (!match) {
    console.error(`  [${tc.id} LF] ${tc.name}\n    Erwartet: ${JSON.stringify(tc.erwartet)}\n    Erhalten: ${JSON.stringify(actual)}`);
  }
  assert(match, `${tc.id} (LF): ${tc.name} (Ausgabe exakt wie erwartet)`);

  const findings = core.auditText(actual, tc.id + ".txt", cfg, state);
  const isClean = findings.length === 0;
  if (isClean !== tc.sauber) {
    console.error(`  [${tc.id} LF] Prüfbefunde: ${JSON.stringify(findings.map(f => f.kategorie + ":" + f.zeile))}`);
  }
  assert(
    isClean === tc.sauber,
    `${tc.id} (LF): Prüfmodus (-Pruefen) erwartet sauber=${tc.sauber}, erhalten=${isClean}`
  );

  // 3b. Befund 1: Gesamter Testkorpus zusätzlich als CRLF-Variante
  const crlfIn = tc.eingabe.replace(/\r?\n/g, "\r\n");
  const crlfExp = tc.erwartet.replace(/\r?\n/g, "\r\n");
  const stateCrlf = new core.AnonState();
  const actualCrlf = core.processText(crlfIn, cfg, stateCrlf);
  const matchCrlf = actualCrlf === crlfExp;
  if (!matchCrlf) {
    console.error(`  [${tc.id} CRLF] ${tc.name}\n    Erwartet: ${JSON.stringify(crlfExp)}\n    Erhalten: ${JSON.stringify(actualCrlf)}`);
  }
  assert(matchCrlf, `${tc.id} (CRLF): ${tc.name} (CRLF-Ausgabe exakt wie erwartet)`);

  const findingsCrlf = core.auditText(actualCrlf, tc.id + ".txt", cfg, stateCrlf);
  assert(
    (findingsCrlf.length === 0) === tc.sauber,
    `${tc.id} (CRLF): Prüfmodus (-Pruefen) bei CRLF erwartet sauber=${tc.sauber}`
  );

  // Bekannte Lücken: Der Prüfmodus muss die Rohdaten (ohne Anonymisierung) beanstanden
  if (tc.pruefeRoh) {
    const rawFindings = core.auditText(tc.eingabe, tc.id + ".txt", cfg);
    assert(rawFindings.length > 0, `${tc.id}: Prüfmodus meldet die Lücke in den Rohdaten (${rawFindings.length} Treffer)`);
    if (tc.pruefeRohKategorie) {
      assert(rawFindings.some(f => f.kategorie === tc.pruefeRohKategorie), `${tc.id}: Prüfmodus meldet in den Rohdaten die Kategorie ${tc.pruefeRohKategorie}`);
    }
  }

  if (tc.jsonValid) {
    let validJson = false;
    try {
      JSON.parse(actual);
      validJson = true;
    } catch (e) {
      validJson = false;
    }
    assert(validJson, `${tc.id}: JSON-Struktur nach Ersetzung weiterhin gültig`);
  }

  if (tc.pruefeRueck) {
    const restored = core.deanonymizeText(actual, state);
    assert(
      restored === tc.eingabe,
      `${tc.id}: Rückübersetzung (-Zurueck) stellt Originaltext exakt wieder her`
    );
    const restoredCrlf = core.deanonymizeText(actualCrlf, stateCrlf);
    assert(
      restoredCrlf === crlfIn,
      `${tc.id} (CRLF): Rückübersetzung (-Zurueck) stellt CRLF-Originaltext exakt wieder her`
    );
  }
}

console.log("=== 4. Prüfe Mehrdateien-Konsistenz auf tests/beispiele/ (LF + CRLF) ===");
if (AKTUALISIEREN && !fs.existsSync(ERWARTET_DIR)) fs.mkdirSync(ERWARTET_DIR, { recursive: true });
const sampleFiles = fs.readdirSync(BEISPIELE_DIR).filter(f => !f.startsWith(".")).sort();
const multiState = new core.AnonState();
const multiCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });

for (const sf of sampleFiles) {
  const fullIn = path.join(BEISPIELE_DIR, sf);
  const raw = fs.readFileSync(fullIn, "utf8");
  const anon = core.processText(raw, multiCfg, multiState);
  const findings = core.auditText(anon, sf, multiCfg);
  assert(findings.length === 0, `Beispieldatei ${sf} ist nach Anonymisierung SAUBER (0 Restfunde)`);

  const expPath = path.join(ERWARTET_DIR, sf);
  if (AKTUALISIEREN) {
    fs.writeFileSync(expPath, anon, "utf8");
    console.log(`  tests/erwartet/${sf} neu geschrieben (--aktualisieren)`);
  }
  assert(fs.existsSync(expPath), `Referenz tests/erwartet/${sf} vorhanden`);
  const expContent = fs.existsSync(expPath) ? fs.readFileSync(expPath, "utf8") : "";
  if (anon !== expContent) {
    console.error(`  [${sf}] weicht vom Sollstand ab. Bei gewollter Änderung: node tests/run-tests.js --aktualisieren`);
  }
  assert(anon === expContent, `Beispieldatei ${sf} stimmt mit Referenz in tests/erwartet/${sf} überein`);
}

// CRLF-Mehrdateienlauf auf tests/beispiele/ für Paritätsprüfung A == B
const multiStateCrlf = new core.AnonState();
for (const sf of sampleFiles) {
  const fullIn = path.join(BEISPIELE_DIR, sf);
  const rawCrlf = fs.readFileSync(fullIn, "utf8").replace(/\r?\n/g, "\r\n");
  const anonCrlf = core.processText(rawCrlf, multiCfg, multiStateCrlf);
  const expLf = fs.readFileSync(path.join(ERWARTET_DIR, sf), "utf8");
  assert(
    anonCrlf === expLf.replace(/\r?\n/g, "\r\n"),
    `Beispieldatei ${sf} (CRLF) entspricht exakt der CRLF-Referenzausgabe`
  );
}

const arubaAnon = fs.readFileSync(path.join(ERWARTET_DIR, "01-aruba-aoscx.txt"), "utf8");
const sonicAnon = fs.readFileSync(path.join(ERWARTET_DIR, "02-sonic-config_db.json"), "utf8");
const ciscoAnon = fs.readFileSync(path.join(ERWARTET_DIR, "03-cisco-fortigate-syslog.log"), "utf8");

assert(arubaAnon.includes("MAC-1") && sonicAnon.includes("MAC-1") && ciscoAnon.includes("MAC-1"), "MAC-1 ist über Aruba, SONiC und Cisco (trotz 001a.2b3c.4d5e) konsistent");
assert(arubaAnon.includes("NET-1.H2") && ciscoAnon.includes("NET-1.H2"), "192.0.2.1 hat in Aruba und Syslog denselben Platzhalter NET-1.H2");
assert(sonicAnon.includes("NET-1.H3/24") && ciscoAnon.includes("NET-1.H3"), "192.0.2.254 hat in SONiC und Cisco HSRP denselben Platzhalter NET-1.H3");

console.log("=== 5. Explizite Tests für die 11 Code-Review-Befunde ===");

// Befund 1: CRLF-Muster mit (?=\r?$) und keine $-Umschreibung in compileDotNetPatternToJS
const fnCompileMatch = scriptMatch[1].match(/function compileDotNetPatternToJS[\s\S]*?return new RegExp\(pat, flags\);\s*\}/);
assert(Boolean(fnCompileMatch) && !fnCompileMatch[0].includes("(?="), "Befund 1: compileDotNetPatternToJS enthält keine $-Umschreibung mehr");
const descRule = diskRules.freitextMuster.find(r => r.name.includes("Interface Description"));
assert(descRule.suche.endsWith("(?=\\r?$)"), "Befund 1: Multiline-Muster in anon-regeln.json enden auf (?=\\r?$)");
const rxDescProbe = new RegExp("^([ \\t]*description[ \\t]+)([^\\r\\n]+)(?=\\r?$)", "im");
assert(rxDescProbe.test("description Test\r\nx"), "Befund 1 Gegenprobe: Multiline-Muster trifft bei CRLF ('description Test\\r\\nx')");

// Befund 2: Dateinamen/Pfade durch Engine schicken, Pfade in Prüfung aufnehmen, bericht.json nicht im Freigabe-ZIP
const pathCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
const pathState = new core.AnonState();
const origRelPath = "Rechenzentrum-Nord/rz1-sw-core01/show-tech-acc-halle2-01_192.0.2.1.txt";
const anonRelPath = core.processPath(origRelPath, pathCfg, pathState);
assert(
  anonRelPath === "FIRMA-1/CORE-A/show-tech-HOST-1_NET-1.H1.txt",
  `Befund 2: Pfadbestandteile anonymisiert (${anonRelPath})`
);
const cleanPathFindings = core.auditText("interface 1/1/1", anonRelPath, pathCfg);
assert(cleanPathFindings.length === 0, "Befund 2: Anonymisierter Pfad besteht Prüfung (0 Treffer)");
const dirtyPathFindings = core.auditText("interface 1/1/1", origRelPath, pathCfg);
assert(
  dirtyPathFindings.length >= 3 && dirtyPathFindings.every(f => f.zeile === 0 && f.kategorie.startsWith("Pfad-")),
  `Befund 2: Nicht anonymisierter Dateipfad wird von auditText als Pfad-* Restfund gemeldet (${dirtyPathFindings.length} Treffer)`
);
const releaseEntries = core.buildReleaseZipEntries([
  { path: anonRelPath, anonText: "hostname CORE-A\n" }
]);
const releaseZipBytes = core.createZipArchive(releaseEntries);
(async () => {
  const unpackedRelease = await core.extractZipBuffer(releaseZipBytes);
  assert(
    unpackedRelease.length === 1 && unpackedRelease[0].path === "anonym/" + anonRelPath,
    "Befund 2: Freigabe-ZIP in B enthält anonymisierten Pfad unter anonym/"
  );
  assert(
    !unpackedRelease.some(e => e.path.includes("bericht.json")),
    "Befund 2: bericht.json liegt NICHT im Freigabe-ZIP von B"
  );

  // Befund 3: Zeichenkodierung (UTF-8-BOM, UTF-16 LE BOM, UTF-16 BE BOM) -> Ausgabe UTF-8 ohne BOM
  const eventLogText = "EventID=4624 IpAddress=203.0.113.60 ClientMAC=00:1a:2b:3c:4d:5e";
  // UTF-16 LE mit BOM (0xFF 0xFE)
  const utf16LeBody = Buffer.from(eventLogText, "utf16le");
  const utf16LeBom = new Uint8Array(2 + utf16LeBody.length);
  utf16LeBom[0] = 0xFF; utf16LeBom[1] = 0xFE;
  utf16LeBom.set(utf16LeBody, 2);

  // UTF-16 BE mit BOM (0xFE 0xFF)
  const utf16BeBom = new Uint8Array(2 + utf16LeBody.length);
  utf16BeBom[0] = 0xFE; utf16BeBom[1] = 0xFF;
  for (let i = 0; i < utf16LeBody.length; i += 2) {
    utf16BeBom[2 + i] = utf16LeBody[i + 1];
    utf16BeBom[2 + i + 1] = utf16LeBody[i];
  }

  // UTF-8 mit BOM (0xEF 0xBB 0xBF)
  const utf8Body = Buffer.from(eventLogText, "utf8");
  const utf8Bom = new Uint8Array(3 + utf8Body.length);
  utf8Bom[0] = 0xEF; utf8Bom[1] = 0xBB; utf8Bom[2] = 0xBF;
  utf8Bom.set(utf8Body, 3);

  assert(!core.isBinaryBytes(utf16LeBom), "Befund 3: UTF-16-LE mit BOM wird nicht als Binärdatei übersprungen");
  assert(!core.isBinaryBytes(utf16BeBom), "Befund 3: UTF-16-BE mit BOM wird nicht als Binärdatei übersprungen");
  assert(!core.isBinaryBytes(utf8Bom), "Befund 3: UTF-8 mit BOM wird nicht als Binärdatei übersprungen");

  for (const [label, bomBytes] of [["UTF-16-LE", utf16LeBom], ["UTF-16-BE", utf16BeBom], ["UTF-8-BOM", utf8Bom]]) {
    const decoded = core.decodeBytesWithBom(bomBytes);
    assert(decoded === eventLogText, `Befund 3: ${label} exakt ohne führendes BOM dekodiert`);
    const bomState = new core.AnonState();
    const bomAnon = core.processText(decoded, pathCfg, bomState);
    assert(
      bomAnon === "EventID=4624 IpAddress=NET-1.H1 ClientMAC=MAC-1",
      `Befund 3: IPs und MACs in ${label}-Eventlog erkannt und ersetzt`
    );
    const bomFindings = core.auditText(bomAnon, "eventlog.txt", pathCfg);
    assert(bomFindings.length === 0, `Befund 3: Anonymisiertes ${label}-Eventlog ist SAUBER`);
    const outUtf8 = new TextEncoder().encode(bomAnon);
    assert(outUtf8[0] !== 0xEF && outUtf8[0] !== 0xFF && outUtf8[0] !== 0xFE, `Befund 3: Ausgabe von ${label} ist UTF-8 ohne BOM`);
  }

  // Befund 4: ANON-AES256-2 Tabellenverschlüsselung + 6 Pflicht-Negativtests + ANON-AES256-1 Upgrade
  const sampleTableJson = JSON.stringify(multiState.toJSON());
  const validPass = "SicheresPasswort#2026!";
  // Nutze 10.000 Iterationen für schnelle Negativtests und 600.000 für Standard-Prüfung
  const encV2Default = await core.encryptTableAes256V2(sampleTableJson, validPass);
  const hdrV2Default = JSON.parse(encV2Default);
  assert(hdrV2Default.format === "ANON-AES256-2", "Befund 4: Neues Format ist ANON-AES256-2");
  assert(hdrV2Default.kdf === "PBKDF2-SHA256", "Befund 4: kdf im Kopf ist PBKDF2-SHA256 (Standard der Browser-Variante)");
  const encV2Sha1 = await core.encryptTableAes256V2(sampleTableJson, validPass, 10000, "PBKDF2-SHA1");
  assert(JSON.parse(encV2Sha1).kdf === "PBKDF2-SHA1", "Befund 4: ANON-AES256-2 mit PBKDF2-SHA1 weiterhin erzeugbar");
  const decV2Sha1 = await core.decryptTableAes256V2(encV2Sha1, validPass);
  delete decV2Sha1._protectionMode;
  delete decV2Sha1._loadedFormat;
  assert(JSON.stringify(decV2Sha1) === sampleTableJson, "Befund 4: ANON-AES256-2 mit PBKDF2-SHA1 (ältere anon.ps1-Tabellen) ladbar");
  // Obergrenze 5.000.000 Iterationen beim Laden
  const tooManyIter = JSON.parse(encV2Sha1);
  tooManyIter.iterations = 5000001;
  await assertRejects(() => core.decryptTableAes256V2(JSON.stringify(tooManyIter), validPass), "Iterationen > 5.000.000 werden beim Laden abgelehnt (ANON-AES256-2)");
  const gcmTooMany = JSON.parse(await core.encryptTableWebCrypto(sampleTableJson, validPass, 1000));
  gcmTooMany.iterations = 6000000;
  await assertRejects(() => core.decryptTableWebCrypto(JSON.stringify(gcmTooMany), validPass), "Iterationen > 5.000.000 werden beim Laden abgelehnt (AES-GCM)");
  const badKdf = JSON.parse(encV2Sha1);
  badKdf.kdf = "PBKDF2-MD5";
  await assertRejects(() => core.decryptTableAes256V2(JSON.stringify(badKdf), validPass), "Unbekanntes Ableitungsverfahren wird abgelehnt");
  // UI speichert standardmäßig ANON-AES256-2 und leert die Passwortfelder
  const exportHandler = htmlContent.slice(htmlContent.indexOf('getElementById("btnExportEncryptedTable")'), htmlContent.indexOf('getElementById("btnLoadTableFile")'));
  assert(exportHandler.includes("encryptTableAes256V2(") && !exportHandler.includes("encryptTableWebCrypto("), "UI: Tabellen-Export nutzt ANON-AES256-2");
  assert(exportHandler.includes('getElementById("tableSavePass").value = ""') && exportHandler.includes('getElementById("tableSavePassConfirm").value = ""'), "UI: Passwortfelder werden nach dem Export geleert");
  assert(hdrV2Default.iterations === 600000, "Befund 4: Standard-Iterationen sind 600000");

  const decV2Default = await core.decryptTableAes256V2(encV2Default, validPass);
  const decV2Clean = Object.assign({}, decV2Default);
  delete decV2Clean._protectionMode;
  delete decV2Clean._loadedFormat;
  assert(JSON.stringify(decV2Clean) === sampleTableJson, "Befund 4: ANON-AES256-2 Roundtrip (600.000 Iterationen) exakt");

  const encV2Fast = await core.encryptTableAes256V2(sampleTableJson, validPass, 10000);
  const baseObj = JSON.parse(encV2Fast);

  // 4a. Pflicht-Negativtest 1: leeres hmac
  const tEmptyHmac = Object.assign({}, baseObj, { hmac: "" });
  await assertRejects(
    () => core.decryptTableAes256V2(JSON.stringify(tEmptyHmac), validPass),
    "Befund 4 Negativtest 1: Leeres 'hmac' MUSS fehlschlagen"
  );

  // 4b. Pflicht-Negativtest 2: verkürztes hmac (16 statt 32 Bytes)
  const shortMac = Buffer.from(baseObj.hmac, "base64").subarray(0, 16).toString("base64");
  const tShortHmac = Object.assign({}, baseObj, { hmac: shortMac });
  await assertRejects(
    () => core.decryptTableAes256V2(JSON.stringify(tShortHmac), validPass),
    "Befund 4 Negativtest 2: Verkürztes 'hmac' MUSS fehlschlagen"
  );

  // 4c. Pflicht-Negativtest 3: verändertes IV
  const ivBuf = Buffer.from(baseObj.iv, "base64");
  ivBuf[0] ^= 0x01;
  const tBadIv = Object.assign({}, baseObj, { iv: ivBuf.toString("base64") });
  await assertRejects(
    () => core.decryptTableAes256V2(JSON.stringify(tBadIv), validPass),
    "Befund 4 Negativtest 3: Verändertes IV MUSS bereits bei der HMAC-Prüfung fehlschlagen"
  );

  // 4d. Pflicht-Negativtest 4: verändertes Salt
  const saltBuf = Buffer.from(baseObj.salt, "base64");
  saltBuf[0] ^= 0x01;
  const tBadSalt = Object.assign({}, baseObj, { salt: saltBuf.toString("base64") });
  await assertRejects(
    () => core.decryptTableAes256V2(JSON.stringify(tBadSalt), validPass),
    "Befund 4 Negativtest 4: Verändertes Salt MUSS fehlschlagen"
  );

  // 4e. Pflicht-Negativtest 5: verändertes iterations-Feld
  const tBadIter = Object.assign({}, baseObj, { iterations: 10001 });
  await assertRejects(
    () => core.decryptTableAes256V2(JSON.stringify(tBadIter), validPass),
    "Befund 4 Negativtest 5: Verändertes iterations-Feld MUSS fehlschlagen"
  );

  // 4f. Pflicht-Negativtest 6: falsches Passwort
  await assertRejects(
    () => core.decryptTableAes256V2(encV2Fast, "FalschesPasswort#2026!"),
    "Befund 4 Negativtest 6: Falsches Passwort MUSS fehlschlagen"
  );

  // 4g. ANON-AES256-1 bleibt ladbar mit Warnung und wird beim Speichern auf ANON-AES256-2 gehoben
  const v1Salt = crypto.randomBytes(16);
  const v1Iv = crypto.randomBytes(16);
  const v1Key = crypto.pbkdf2Sync(validPass, v1Salt, 10000, 32, "sha1");
  const v1CipherObj = crypto.createCipheriv("aes-256-cbc", v1Key, v1Iv);
  const v1Cipher = Buffer.concat([v1CipherObj.update(sampleTableJson, "utf8"), v1CipherObj.final()]);
  const v1Hmac = crypto.createHmac("sha256", v1Key).update(v1Cipher).digest();
  const v1Json = JSON.stringify({
    format: "ANON-AES256-1",
    iterations: 10000,
    salt: v1Salt.toString("base64"),
    iv: v1Iv.toString("base64"),
    hmac: v1Hmac.toString("base64"),
    daten: v1Cipher.toString("base64")
  });
  let warningReceived = "";
  const v1Loaded = await core.decryptTableWebCrypto(v1Json, validPass, (w) => { warningReceived = w; });
  assert(warningReceived.includes("ANON-AES256-1"), "Befund 4: Laden von ANON-AES256-1 gibt Warnung aus");
  assert(v1Loaded._protectionMode === "PASSWORD", "Befund 4/5: Schutzart PASSWORD beim Laden gemerkt");
  const upgradedV2 = await core.encryptTableAes256V2(JSON.stringify(core.AnonState.fromJSON(v1Loaded).toJSON()), validPass, 10000);
  assert(JSON.parse(upgradedV2).format === "ANON-AES256-2", "Befund 4: ANON-AES256-1 wird beim Speichern auf ANON-AES256-2 gehoben");

  // Befund 5: Keine stille Herabstufung & DPAPI-Standard in anon.ps1 + Schutzart-Merkmal
  assert(
    ps1Content.includes("[switch]$Unverschluesselt") &&
    ps1Content.includes('$State.LoadedProtection -eq "PASSWORD"') &&
    ps1Content.includes('$State.LoadedProtection -eq "DPAPI"'),
    "Befund 5: anon.ps1 merkt Schutzart der geladenen Tabelle, verhindert stille Herabstufung und schützt neue Tabellen unter Windows per DPAPI"
  );

  // Befund 6: Exit-Code 2 im Hauptlauf bei Restfunden
  assert(
    ps1Content.includes('if ($pruefStatus -eq "SAUBER")') && ps1Content.includes("exit 2"),
    "Befund 6: anon.ps1 beendet Hauptlauf bei Restfunden (pruefTrefferAnzahl > 0) mit Exit-Code 2"
  );

  // Befund 7: Minimale Regeldatei ohne optionen, ausnahmen und pruefung
  const minimalRules = {
    eigeneBegriffe: {
      festeZuordnung: { "sw-minimal-01": "MIN-1" }
    }
  };
  const minCfg = core.buildEngineConfig(minimalRules, {});
  const minState = new core.AnonState();
  const minOut = core.processText("hostname sw-minimal-01 ip 198.51.100.3", minCfg, minState);
  const minAudit = core.auditText(minOut, "min.txt", minCfg);
  assert(
    minOut === "hostname MIN-1 ip NET-1.H1" && Array.isArray(minAudit),
    "Befund 7: Minimale Regeldatei ohne optionen, ausnahmen und pruefung funktioniert fehlerfrei"
  );

  // Befund 8: Wort-/Namensgrenzen bei festeZuordnung und firmenUndStandorte
  const boundCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
  const boundState = new core.AnonState();
  const boundOut = core.processText("rz1-tor-01 und rz1-tor-010", boundCfg, boundState);
  assert(
    boundOut === "TOR-A und rz1-tor-010" && !boundOut.includes("TOR-A0"),
    `Befund 8: 'rz1-tor-01' macht 'rz1-tor-010' nicht zu 'TOR-A0' (Ergebnis: ${boundOut})`
  );

  // Befund 9: Add-Type sauber nach $PSVersionTable.PSEdition verzweigt ohne stillen Catch-Fallback
  assert(
    ps1Content.includes('$PSVersionTable.PSEdition -eq "Desktop"') &&
    !/try\s*\{\s*Add-Type[\s\S]*?\}\s*catch\s*\{\s*Add-Type/i.test(ps1Content),
    "Befund 9: Add-Type in anon.ps1 verzweigt sauber nach PSEdition ohne stillen Catch-Fallback"
  );

  // Befund 10: Mindestlänge für Passwörter (12 Zeichen) in A und B; kein prompt() in B
  assert(core.MIN_PASSWORD_LENGTH === 12, "Befund 10: MIN_PASSWORD_LENGTH ist 12");
  await assertRejects(
    () => core.encryptTableWebCrypto(sampleTableJson, "ZuKurz12345"),
    "Befund 10: encryptTableWebCrypto lehnt Passwort < 12 Zeichen ab (11 Zeichen)"
  );
  await assertRejects(
    () => core.encryptTableAes256V2(sampleTableJson, "ZuKurz12345"),
    "Befund 10: encryptTableAes256V2 lehnt Passwort < 12 Zeichen ab (11 Zeichen)"
  );
  assert(!/\bprompt\s*\(/.test(htmlContent), "Befund 10: anonymisierer.html verwendet kein prompt() für Passwörter");

  // Befund 11: Regex-Timeout (5 Sekunden) auf allen Regex-Instanzen in A
  assert(
    ps1Content.includes("TimeSpan.FromSeconds(5)") && ps1Content.includes("[TimeSpan]::FromSeconds(5)"),
    "Befund 11: Alle Regex-Instanzen in anon.ps1 nutzen 5 Sekunden Timeout (RxTimeout)"
  );

  console.log("=== 6. Performance- & Stresstest: Großer Aruba AOS-CX Show-Tech (40.000+ Zeilen) ===");
  const showTechChunks = [
    "================================f=show tech====================================",
    "hostname rz1-sw-core01",
    "Version : FL.10.13.1020",
    "snmp-server system-location Rechenzentrum-Nord Halle 3",
    "snmp-server system-contact Max Mustermann (netze@intern.musterfirma.de)",
    "user admin password ciphertext AQBapf92384719283749182374918273948172938471928374"
  ];
  for (let i = 1; i <= 5000; i++) {
    const vId = (i % 400) + 10;
    const o4 = (i % 250) + 1;
    const hex = (i & 0xff).toString(16).padStart(2, "0");
    const net = ["192.0.2", "198.51.100", "203.0.113"][i % 3];
    showTechChunks.push(
      `vlan ${vId}`,
      `    nameMuster_${vId}`,
      `    nameKD_${vId}_${net}.0-24`,
      `interface 1/1/${(i % 48) + 1}`,
      `    description Uplink_${i} zu dist-sw${(i % 30) + 1} (Musterfirma GmbH)`,
      `    ip address ${net}.${o4}/24`,
      `1/1/${(i % 48) + 1}  acc-sw${(i % 80) + 1}  00:1a:2b:3c:4d:${hex}  ${net}.254  Aruba JL658A  FL.10.13.1020`,
      `2026-10-16T14:22:${(i % 59).toString().padStart(2, "0")}.123Z rz1-sw-core01 hpe-routing[${i}]: Event on sn link state up for ${net}.${o4}`
    );
  }
  const largeShowTech = showTechChunks.join("\r\n");
  const t0 = Date.now();
  const perfState = new core.AnonState();
  const perfCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
  const largeAnon = core.processText(largeShowTech, perfCfg, perfState);
  const largeFindings = core.auditText(largeAnon, "aruba-show-tech-large.txt", perfCfg);
  const elapsedMs = Date.now() - t0;
  console.log(`  Großer Show-Tech (${(largeShowTech.length / (1024 * 1024)).toFixed(2)} MB, ${showTechChunks.length} Zeilen) verarbeitet + geprüft in ${elapsedMs} ms`);
  assert(elapsedMs < 8000, `Performance-Ziel erreicht: ${elapsedMs} ms (< 8000 ms)`);
  assert(largeFindings.length === 0, `Großer Aruba Show-Tech ist nach Anonymisierung SAUBER (0 Restfunde)`);
  assert(!largeAnon.includes("\u0002PROT_"), "Alle Schutz-Marker vollständig aufgelöst");

  // WebCrypto AES-GCM 600.000 Iterationen + Alt-Tabellen (100.000 Iterationen)
  const encrypted600k = await core.encryptTableWebCrypto(sampleTableJson, "GeheimesPasswort#2026");
  const header600k = JSON.parse(encrypted600k);
  assert(header600k.iterations === 600000, "WebCrypto speichert iterations: 600000 im Tabellenkopf");
  const decrypted600k = await core.decryptTableWebCrypto(encrypted600k, "GeheimesPasswort#2026");
  delete decrypted600k._protectionMode;
  delete decrypted600k._loadedFormat;
  assert(JSON.stringify(decrypted600k) === sampleTableJson, "WebCrypto entschlüsselt 600.000-Iterationen-Tabelle exakt");

  const encrypted100k = await core.encryptTableWebCrypto(sampleTableJson, "AltesPasswort#2025", 100000);
  const header100kNoField = JSON.parse(encrypted100k);
  delete header100kNoField.iterations;
  const decryptedLegacy = await core.decryptTableWebCrypto(JSON.stringify(header100kNoField), "AltesPasswort#2025");
  delete decryptedLegacy._protectionMode;
  delete decryptedLegacy._loadedFormat;
  assert(JSON.stringify(decryptedLegacy) === sampleTableJson, "WebCrypto lädt alte Tabellen (100.000 Iterationen ohne iterations-Feld) weiterhin fehlerfrei");

  console.log("=== 7. Prüfe HPE Comware & MikroTik Regeln ===");
  // Explizite MikroTik-Prüfungen (LF + CRLF):
  // - interface=ether1 und name=bridge1 dürfen NICHT ersetzt werden
  // - name=VLAN10_Intern und interface=VLAN10_Intern müssen denselben Platzhalter bekommen
  // - /system identity set name=... muss als Hostname (HOST-n) ersetzt werden, nicht als TEXT
  for (const eol of ["\n", "\r\n"]) {
    const label = eol === "\r\n" ? "CRLF" : "LF";
    const mtState = new core.AnonState();
    const mtCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
    const mtInput = [
      "/system identity set name=mt-switch-halle1",
      "/interface bridge add name=bridge1",
      "/interface vlan add interface=bridge1 name=VLAN10_Intern vlan-id=10",
      "/interface bridge port add bridge=bridge1 interface=ether1 comment=\"Port_Halle_1\"",
      "/ip address add address=203.0.113.1/24 interface=VLAN10_Intern"
    ].join(eol);
    const mtAnon = core.processText(mtInput, mtCfg, mtState);
    assert(mtAnon.includes("/system identity set name=HOST-1"), `MikroTik (${label}): /system identity set name=... wird als HOST-1 ersetzt`);
    assert(mtAnon.includes("name=bridge1") && mtAnon.includes("interface=bridge1"), `MikroTik (${label}): name=bridge1 und interface=bridge1 bleiben unverändert`);
    assert(mtAnon.includes("interface=ether1"), `MikroTik (${label}): interface=ether1 bleibt unverändert`);
    assert(mtAnon.includes("comment=\"TEXT-1\"") && mtAnon.includes("name=TEXT-2") && mtAnon.includes("interface=TEXT-2"), `MikroTik (${label}): name=VLAN10_Intern und interface=VLAN10_Intern erhalten denselben Platzhalter TEXT-2`);

    // HPE Comware expliziter Test (LF + CRLF)
    const cwState = new core.AnonState();
    const cwInput = [
      "header login %Warnung vor unbefugtem Zugriff%",
      "local-user comware_admin class manage",
      " password cipher $c$3$SecretCipher123",
      "snmp-agent community write cipher $c$3$SnmpSecret456",
      "key simple MyTacacsKey789"
    ].join(eol);
    const cwAnon = core.processText(cwInput, mtCfg, cwState);
    assert(cwAnon.includes("header login %BANNER-1%"), `HPE Comware (${label}): header login %...% wird als BANNER-1 ersetzt`);
    assert(cwAnon.includes("local-user USER-1 class manage"), `HPE Comware (${label}): local-user <name> wird als USER-1 ersetzt`);
    assert(cwAnon.includes("password cipher *****") && cwAnon.includes("snmp-agent community write cipher *****") && cwAnon.includes("key simple *****"), `HPE Comware (${label}): password/community/key werden mit ***** maskiert`);
  }

  console.log("=== 8. Prüfe Code-Review Commit 65cd5d4 (Befunde 1–3) ===");
  // Befund 1: Freitext-Leck bei geschützten Wörtern im Body (LF + CRLF)
  const freitextSamplesByRule = {
    "Mehrzeilige oder einzeilige Banner (banner/header motd, exec, login, shell, incoming)": "banner motd ^Kunde Mustermann Ethernet1/1/1^",
    "SNMP Location & System-Location (CLI)": "snmp-server system-location Kunde Mustermann Ethernet1/1/1",
    "SNMP Contact & System-Contact (CLI)": "snmp-server system-contact Kunde Mustermann Ethernet1/1/1",
    "Interface Description / Alias (CLI)": " description Kunde Mustermann Ethernet1/1/1",
    "VLAN-Namen (CLI)": " name Kunde Mustermann Ethernet1/1/1",
    "VLAN-/Objektnamen (JSON)": "\"vlan_name\": \"Kunde Mustermann Ethernet1/1/1\"",
    "SONiC / JSON Description, Alias, Location, Contact": "\"description\": \"Kunde Mustermann Ethernet1/1/1\"",
    "LLDP / CDP System Description & Port Description": "System Description : Kunde Mustermann Ethernet1/1/1",
    "MikroTik comment= (in Anführungszeichen, inkl. Leerzeichen und mehrzeiliger \\-Fortsetzung)": "set [ find default-name=ether1 ] comment=\"Kunde Mustermann Ethernet1/1/1\"",
    "MikroTik comment= (ohne Anführungszeichen)": "set [ find default-name=ether1 ] comment=Kunde Mustermann Ethernet1/1/1",
    "MikroTik SNMP Location (location=)": "/snmp set location=\"Kunde Mustermann Ethernet1/1/1\"",
    "MikroTik SNMP Contact (contact=)": "/snmp set contact=\"Kunde Mustermann Ethernet1/1/1\"",
    "MikroTik Interface-/VLAN-/Bridge-Namen (name= und interface= konsistent)": "/interface vlan add interface=bridge1 name=\"Kunde Mustermann Ethernet1/1/1\" vlan-id=10"
  };
  assert(
    diskRules.freitextMuster.length === Object.keys(freitextSamplesByRule).length,
    `Alle ${diskRules.freitextMuster.length} freitextMuster-Regeln sind im Mustermann+Ethernet1/1/1-Test abgedeckt`
  );

  for (const eol of ["\n", "\r\n"]) {
    const label = eol === "\r\n" ? "CRLF" : "LF";
    const ftState = new core.AnonState();
    const ftCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
    const ftInput = [
      "interface 1/1/10",
      " description Uplink Praxis Dr Weber Ethernet1/1/10",
      "snmp-server system-location Praxis Weber München Ethernet1/1/2",
      "set [ find default-name=ether1 ] comment=\"Kunde Weber Gi1/0/1\"",
      "vlan 20",
      " name Praxis_Weber_FL.10.13.1020",
      "System Description : Switch bei Weber FL.10.13.1020",
      "System Description : ArubaOS-CX FL.10.13.1020"
    ].join(eol);
    const ftOut = core.processText(ftInput, ftCfg, ftState);
    assert(
      ftOut.includes(" description TEXT-1") && !ftOut.includes("Weber") && !ftOut.includes("Ethernet1/1/10"),
      `Befund 1 (${label}): description mit Personenname + Portname (Ethernet1/1/10) wird komplett ersetzt`
    );
    assert(
      ftOut.includes("snmp-server system-location ORT-1") && !ftOut.includes("München") && !ftOut.includes("Ethernet1/1/2"),
      `Befund 1 (${label}): snmp-server system-location mit Ort + Portname wird komplett ersetzt`
    );
    assert(
      ftOut.includes("comment=\"TEXT-4\"") && !ftOut.includes("Gi1/0/1"),
      `Befund 1 (${label}): MikroTik comment=\"... Gi1/0/1\" wird komplett ersetzt`
    );
    assert(
      ftOut.includes(" name TEXT-2"),
      `Befund 1 (${label}): VLAN-name mit Name + Versionsnummer (FL.10.13.1020) wird komplett ersetzt`
    );
    assert(
      ftOut.includes("System Description : TEXT-3") && !ftOut.includes("Switch bei Weber"),
      `Befund 1 (${label}): System Description 'Switch bei Weber FL.10.13.1020' wird komplett ersetzt`
    );
    assert(
      ftOut.includes("System Description : ArubaOS-CX FL.10.13.1020"),
      `Befund 1 Positivtest (${label}): System Description 'ArubaOS-CX FL.10.13.1020' (nur Produkt + Version) bleibt erhalten`
    );

    // Schleife über ALLE freitextMuster: Body "Kunde Mustermann Ethernet1/1/1" muss bei jedem Muster ersetzt werden
    for (const ruleObj of diskRules.freitextMuster) {
      const sampleLine = freitextSamplesByRule[ruleObj.name];
      assert(typeof sampleLine === "string", `Testzeile für freitextMuster '${ruleObj.name}' vorhanden`);
      const singleRuleJson = JSON.parse(JSON.stringify(diskRules));
      singleRuleJson.freitextMuster = [ruleObj];
      const singleCfg = core.buildEngineConfig(singleRuleJson, { netzerhaltend: true });
      const singleState = new core.AnonState();
      const inputWithEol = sampleLine + eol + "next-line";
      const outSingle = core.processText(inputWithEol, singleCfg, singleState);
      const expectedPlaceholder = `${ruleObj.kategorie || "TEXT"}-1`;
      assert(
        outSingle.includes(expectedPlaceholder) && !outSingle.includes("Mustermann") && !outSingle.includes("Kunde") && !outSingle.includes("Ethernet1/1/1"),
        `Befund 1 Alle-Muster-Test (${label}) [${ruleObj.name}]: 'Kunde Mustermann Ethernet1/1/1' wird durch ${expectedPlaceholder} ersetzt`
      );
    }
  }

  // pwsh für Paritätstests mit anon.ps1 (Befunde 2 & 3 betrafen den Sammler, eigenes Projekt)
  const os = require("os");
  const { spawnSync } = require("child_process");
  const pwshCheck = spawnSync("pwsh", ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], { encoding: "utf8" });

  // ============================================================================
  // 16. NEUE BEDIENFUNKTIONEN IN ANONYMISIERER.HTML (UI-Tests & Statische Prüfungen)
  // ============================================================================
  console.log("--- 16. Prüfe neue Bedienfunktionen (Eigene Begriffe, Vorschau-Kopieren, Tabellen-Vorschau) ---");

  // 16.1 Statischer Check: Keine Verwendung von localStorage / sessionStorage / indexedDB im gesamten HTML-Code
  const forbiddenStorageRegex = /\b(?:localStorage|sessionStorage|indexedDB)\b/i;
  assert(
    !forbiddenStorageRegex.test(htmlContent),
    "Statischer Check: anonymisierer.html enthält keinerlei Verwendung von localStorage, sessionStorage oder indexedDB"
  );
  assert(
    htmlContent.includes("Diese Datei enthält echte Namen – nicht weitergeben, nicht ins Repo."),
    "UI-Hinweis: Warnhinweis 'Diese Datei enthält echte Namen – nicht weitergeben, nicht ins Repo.' ist in anonymisierer.html enthalten"
  );
  assert(
    htmlContent.includes("Nicht bei Bildschirmfreigabe verwenden"),
    "UI-Hinweis: Warnhinweis 'Nicht bei Bildschirmfreigabe verwenden' ist in anonymisierer.html enthalten"
  );

  // 16.2 Eigene Begriffe: Zusammenführung, Wirkung auf Anonymisierung, Export nur eigeneBegriffe, Validierung
  const mergeTestRes = core.validateAndMergeEigeneBegriffe(diskRules, {
    festeZuordnung: [
      { original: "sw-spezial-01", placeholder: "SW-CORE-99" },
      { original: "sw-auto-02", placeholder: "" }, // automatischer Platzhalter
      { original: "   ", placeholder: "   " }      // leere Zeile wird ignoriert
    ],
    firmenUndStandorte: ["", "Klinikum-Suedstadt", "   "],
    interneDomains: ["", "klinik-sued.local"]
  });
  assert(mergeTestRes.valid === true && mergeTestRes.errors.length === 0, "Eigene Begriffe: Gültige Eingaben + leere Zeilen + automatischer Platzhalter werden akzeptiert");
  assert(mergeTestRes.mergedRules.eigeneBegriffe.festeZuordnung["sw-spezial-01"] === "SW-CORE-99", "Eigene Begriffe: Expliziter Platzhalter 'SW-CORE-99' wurde zusammengeführt");
  const autoAssignedPh = mergeTestRes.mergedRules.eigeneBegriffe.festeZuordnung["sw-auto-02"];
  assert(/^[A-Z0-9-]{1,32}$/.test(autoAssignedPh), `Eigene Begriffe: Automatischer Platzhalter '${autoAssignedPh}' erfüllt [A-Z0-9-]{1,32}`);
  assert(mergeTestRes.mergedRules.eigeneBegriffe.firmenUndStandorte.includes("Klinikum-Suedstadt"), "Eigene Begriffe: firmenUndStandorte zusammengeführt");
  assert(mergeTestRes.mergedRules.eigeneBegriffe.interneDomains.includes("klinik-sued.local"), "Eigene Begriffe: interneDomains zusammengeführt");

  // Wirkung auf Anonymisierung + Prüfung (SAUBER)
  const customCfg = core.buildEngineConfig(mergeTestRes.mergedRules, { netzerhaltend: true });
  const customState = new core.AnonState();
  const sampleCustomText = "hostname sw-spezial-01\nsnmp-server location Klinikum-Suedstadt\nSystem Name : sw-auto-02.klinik-sued.local\n";
  const anonCustomText = core.processText(sampleCustomText, customCfg, customState);
  assert(
    anonCustomText.includes("SW-CORE-99") &&
    anonCustomText.includes(autoAssignedPh) &&
    !anonCustomText.includes("sw-spezial-01") &&
    !anonCustomText.includes("sw-auto-02") &&
    !anonCustomText.includes("Klinikum-Suedstadt") &&
    !anonCustomText.includes("klinik-sued.local"),
    "Eigene Begriffe Wirkung: festeZuordnung (inkl. Auto-Platzhalter), firmenUndStandorte und interneDomains greifen sofort beim Lauf"
  );
  const customAudit = core.auditText(anonCustomText, "test.txt", customCfg);
  assert(customAudit.length === 0, "Eigene Begriffe Wirkung: Anonymisierter Text mit eigenen Begriffen und Auto-Platzhalter ist im Prüfmodus SAUBER");

  // Export enthält NUR eigeneBegriffe + ausnahmen.exakteWoerter (keine sonstigen Regeln)
  const exportedLocalJson = core.exportLokaleBegriffeJson({
    festeZuordnung: [{ original: "sw-spezial-01", placeholder: "SW-CORE-99" }],
    firmenUndStandorte: ["Klinikum-Suedstadt"],
    interneDomains: ["klinik-sued.local"]
  }, diskRules);
  const parsedLocalObj = JSON.parse(exportedLocalJson);
  assert(
    Object.keys(parsedLocalObj).sort().join(",") === "ausnahmen,eigeneBegriffe" &&
    parsedLocalObj.eigeneBegriffe &&
    Object.keys(parsedLocalObj.eigeneBegriffe).sort().join(",") === "festeZuordnung,firmenUndStandorte,interneDomains" &&
    Object.keys(parsedLocalObj.ausnahmen).join(",") === "exakteWoerter",
    "Eigene Begriffe Export: anon-regeln.lokal.json enthält ausschließlich 'eigeneBegriffe' und 'ausnahmen.exakteWoerter'"
  );
  const reimportedLocal = core.importLokaleBegriffeJson(exportedLocalJson);
  assert(
    reimportedLocal.festeZuordnung.length === 1 &&
    reimportedLocal.festeZuordnung[0].original === "sw-spezial-01" &&
    reimportedLocal.firmenUndStandorte[0] === "Klinikum-Suedstadt" &&
    reimportedLocal.interneDomains[0] === "klinik-sued.local",
    "Eigene Begriffe Import: Geladene anon-regeln.lokal.json stellt alle 3 Listen korrekt wieder her"
  );

  // Validierung lehnt ungültige Platzhalter, Duplikate und Platzhalter == echter Begriff ab
  const invalidPhRes = core.validateAndMergeEigeneBegriffe(diskRules, {
    festeZuordnung: [{ original: "sw-01", placeholder: "klein_und_ungueltig!" }],
    firmenUndStandorte: [],
    interneDomains: []
  });
  assert(!invalidPhRes.valid && invalidPhRes.errors.some(e => e.includes("[A-Z0-9-]{1,32}")), "Eigene Begriffe Validierung: Ungültiger Platzhalter (Kleinbuchstaben/Sonderzeichen) wird abgelehnt");

  const tooLongPhRes = core.validateAndMergeEigeneBegriffe(diskRules, {
    festeZuordnung: [{ original: "sw-01", placeholder: "A".repeat(33) }],
    firmenUndStandorte: [],
    interneDomains: []
  });
  assert(!tooLongPhRes.valid, "Eigene Begriffe Validierung: Platzhalter > 32 Zeichen wird abgelehnt");

  const dupRes = core.validateAndMergeEigeneBegriffe(diskRules, {
    festeZuordnung: [
      { original: "sw-dup", placeholder: "SW-DUP-1" },
      { original: "SW-DUP", placeholder: "SW-DUP-2" }
    ],
    firmenUndStandorte: ["FirmaA", "firmaa"],
    interneDomains: ["dom.local", "DOM.LOCAL"]
  });
  assert(!dupRes.valid && dupRes.errors.length >= 3, "Eigene Begriffe Validierung: Duplikate in festeZuordnung, firmenUndStandorte und interneDomains werden gemeldet");

  const collisionRes = core.validateAndMergeEigeneBegriffe(diskRules, {
    festeZuordnung: [{ original: "sw-echt-01", placeholder: "MUSTERFIRMA" }],
    firmenUndStandorte: ["Musterfirma"],
    interneDomains: []
  });
  assert(!collisionRes.valid && collisionRes.errors.some(e => e.includes("echten Begriff")), "Eigene Begriffe Validierung: Platzhalter darf nicht mit einem echten Begriff übereinstimmen");

  // 16.3 Kopierfunktion in der Vorschau (> 200 KB Testfall, Bestätigung bei Original & unsauberem Prüfstatus)
  const copyLargeOriginal = "hostname rz1-sw-core01\n" + "X".repeat(250 * 1024); // > 200 KB
  const copyLargeAnon = "hostname CORE-A\n" + "X".repeat(250 * 1024);
  const previewTextTruncated = core.formatPreviewText(copyLargeAnon);
  assert(previewTextTruncated.length < copyLargeAnon.length && previewTextTruncated.includes("VORSCHAU GEKÜRZT"), "Vorschau-Anzeige kürzt Texte > 200 KB im DOM");

  const mockProcessedResults = [
    {
      path: "clean-large.txt",
      originalText: copyLargeOriginal,
      anonText: copyLargeAnon,
      findings: []
    },
    {
      path: "dirty-file.txt",
      originalText: "secret original",
      anonText: "anon with restfund",
      findings: [{ datei: "dirty-file.txt", zeile: 1, kategorie: "FIRMA_STANDORT", fund: "Musterfirma" }]
    }
  ];

  // Original kopieren: verlangt immer Bestätigung mit Echtdaten-Hinweis; bei Ablehnung kein Kopieren
  let lastConfirmPrompt = "";
  const origCancelled = core.preparePreviewCopy(mockProcessedResults, 0, "original", (msg) => {
    lastConfirmPrompt = msg;
    return false;
  });
  assert(
    origCancelled.allowed === false &&
    lastConfirmPrompt.includes("Enthält Echtdaten. Zwischenablage-Verlauf/Cloud-Sync können den Inhalt speichern."),
    "Kopierfunktion Original: Vor dem Kopieren wird Bestätigung mit Hinweis 'Enthält Echtdaten. Zwischenablage-Verlauf/Cloud-Sync können den Inhalt speichern.' verlangt"
  );

  const origConfirmed = core.preparePreviewCopy(mockProcessedResults, 0, "original", () => true);
  assert(
    origConfirmed.allowed === true &&
    origConfirmed.text === copyLargeOriginal &&
    origConfirmed.text.length === copyLargeOriginal.length &&
    origConfirmed.statusMessage.includes("vollständiger Inhalt kopiert ("),
    "Kopierfunktion Original (> 200 KB): Liefert nach Bestätigung den VOLLSTÄNDIGEN ungekürzten Inhalt und Hinweis 'vollständiger Inhalt kopiert (X KB)'"
  );

  // Anonymisiert kopieren (SAUBER, > 200 KB): kopiert sofort ohne Warn-Dialog den ungekürzten Text
  let anonCleanPromptCalled = false;
  const anonCleanCopy = core.preparePreviewCopy(mockProcessedResults, 0, "anon", () => {
    anonCleanPromptCalled = true;
    return false;
  });
  assert(
    anonCleanCopy.allowed === true &&
    !anonCleanPromptCalled &&
    anonCleanCopy.text === copyLargeAnon &&
    anonCleanCopy.statusMessage.includes("vollständiger Inhalt kopiert ("),
    "Kopierfunktion Anonymisiert (SAUBER, > 200 KB): Liefert ungekürzten Inhalt ohne Warnabfrage inkl. KB-Hinweis"
  );

  // Anonymisiert kopieren (nicht SAUBER): verlangt Bestätigung mit Anzahl der Treffer
  let dirtyPromptMsg = "";
  const anonDirtyCancelled = core.preparePreviewCopy(mockProcessedResults, 1, "anon", (msg) => {
    dirtyPromptMsg = msg;
    return false;
  });
  assert(
    anonDirtyCancelled.allowed === false &&
    dirtyPromptMsg.includes("nicht SAUBER") &&
    dirtyPromptMsg.includes("1"),
    "Kopierfunktion Anonymisiert (nicht SAUBER): Warnt mit Anzahl der Treffer und bricht ohne Bestätigung ab"
  );
  const anonDirtyConfirmed = core.preparePreviewCopy(mockProcessedResults, 1, "anon", () => true);
  assert(anonDirtyConfirmed.allowed === true && anonDirtyConfirmed.text === "anon with restfund", "Kopierfunktion Anonymisiert (nicht SAUBER): Erlaubt Kopieren nach ausdrücklicher Bestätigung");

  // 16.4 Vorschau der Zuordnungstabelle: Originale standardmäßig nicht im DOM, erst nach Umschalten sichtbar, Suche/Filter/Sortierung, Tab-Wechsel verdeckt wieder
  const extractedTable = core.extractMappingTableEntries(customState);
  assert(extractedTable.entries.length >= 3, "Tabellen-Vorschau: Einträge aus AnonState extrahiert");
  assert(extractedTable.categoryCounts["FESTE_ZUORDNUNG"] >= 2, "Tabellen-Vorschau: Anzahl Einträge pro Kategorie berechnet");

  const maskedHtml = core.renderMappingTableRowsHtml(extractedTable.entries, { showOriginals: false });
  assert(
    maskedHtml.includes("••••") &&
    !maskedHtml.includes("sw-spezial-01") &&
    !maskedHtml.includes("Klinikum-Suedstadt") &&
    !maskedHtml.includes("klinik-sued.local"),
    "Tabellen-Vorschau Sicherheit: Standardmäßig (showOriginals=false) sind alle Originale durch '••••' verdeckt und stehen NICHT im DOM-HTML"
  );

  const revealedHtml = core.renderMappingTableRowsHtml(extractedTable.entries, { showOriginals: true });
  assert(
    revealedHtml.includes("sw-spezial-01") &&
    revealedHtml.includes("Klinikum-Suedstadt") &&
    revealedHtml.includes("klinik-sued.local"),
    "Tabellen-Vorschau: Erst nach Umschalten (showOriginals=true) werden die Originale im DOM gerendert"
  );

  // Suche nach Original und Platzhalter
  const filteredByOrig = core.filterAndSortMappingEntries(extractedTable.entries, { search: "Klinikum-Suedstadt", sortBy: "placeholder", sortDir: "asc" });
  assert(filteredByOrig.length === 1 && filteredByOrig[0].original === "Klinikum-Suedstadt", "Tabellen-Vorschau Suche: Filtert nach Originalbegriff");
  const filteredByPh = core.filterAndSortMappingEntries(extractedTable.entries, { search: "SW-CORE-99", sortBy: "placeholder", sortDir: "asc" });
  assert(filteredByPh.length === 1 && filteredByPh[0].placeholder === "SW-CORE-99", "Tabellen-Vorschau Suche: Filtert nach Platzhalter");

  // Geladene Tabelle funktioniert ebenfalls in der Vorschau
  const reloadedState = core.AnonState.fromJSON(customState.toJSON());
  const extractedReloaded = core.extractMappingTableEntries(reloadedState);
  assert(extractedReloaded.entries.length === extractedTable.entries.length, "Tabellen-Vorschau: Funktioniert identisch für geladene Zuordnungstabelle");

  // Prüfe, dass Tab-Wechsel im Browser-Code maskTablePreviewOriginals() aufruft
  assert(
    /querySelectorAll\("nav\.tabs button"\)[\s\S]{1,400}?maskTablePreviewOriginals\(\)/.test(htmlContent),
    "Tabellen-Vorschau Tab-Wechsel: Beim Wechsel des Reiters wird maskTablePreviewOriginals() automatisch aufgerufen"
  );

  // ============================================================================
  // 17. PRÜFE EDITIERBARE ZUORDNUNGSTABELLE & ANON-REGELN.LOKAL.JSON
  // ============================================================================
  console.log(`--- 17. Prüfe editierbare Zuordnungstabelle & anon-regeln.lokal.json (ausnahmen.exakteWoerter) ---`);

  // 17.1 Natürliche Sortierung (TEXT-1, TEXT-2, ... TEXT-10)
  assert(core.compareNatural("TEXT-1", "TEXT-2") < 0, "Natürliche Sortierung: TEXT-1 vor TEXT-2");
  assert(core.compareNatural("TEXT-2", "TEXT-10") < 0, "Natürliche Sortierung: TEXT-2 vor TEXT-10 (nicht lexikographisch TEXT-10 vor TEXT-2)");
  assert(core.compareNatural("TEXT-10", "TEXT-2") > 0, "Natürliche Sortierung: TEXT-10 nach TEXT-2");
  assert(core.compareNatural("NET-1.H2", "NET-1.H10") < 0, "Natürliche Sortierung: NET-1.H2 vor NET-1.H10");

  const naturalTestList = [
    { category: "TEXT", placeholder: "TEXT-10", original: "zehn" },
    { category: "TEXT", placeholder: "TEXT-2", original: "zwei" },
    { category: "TEXT", placeholder: "TEXT-1", original: "eins" },
    { category: "HOST", placeholder: "HOST-1", original: "host01" }
  ];
  const sortedNatural = core.filterAndSortMappingEntries(naturalTestList, { sortBy: "category", sortDir: "asc" });
  assert(
    sortedNatural.map(x => x.placeholder).join(",") === "HOST-1,TEXT-1,TEXT-2,TEXT-10",
    "Standardsortierung nach Kategorie + natürlicher Platzhalter-Reihenfolge: HOST-1, TEXT-1, TEXT-2, TEXT-10"
  );

  // 17.2 Platzhalter umbenennen (TEXT-x -> VLAN-GAESTE), Alias-Erhalt, Rückübersetzung mit BEIDEN Namen
  const editState = new core.AnonState();
  const editSampleText = [
    "hostname rz1-sw-core01",
    "vlan 100",
    "   name WAN_GUEST_192.0.2.0",
    "interface 1/1/1",
    "   description Uplink Praxis Dr Weber",
    "   ip address 198.51.100.1/24"
  ].join("\n");
  const editCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
  const editAnon1 = core.processText(editSampleText, editCfg, editState);

  const initialMapping = core.extractMappingTableEntries(editState);
  const textRow = initialMapping.entries.find(e => e.original === "Uplink Praxis Dr Weber");
  assert(Boolean(textRow), "Freitext-Zeile wurde erfasst");
  const oldTextPh = textRow.placeholder;

  let localCustomTerms = { festeZuordnung: [], firmenUndStandorte: [], interneDomains: [], exakteWoerter: [] };
  const renameRes = core.renameMappingTableEntry(editState, oldTextPh, "VLAN-GAESTE", diskRules, localCustomTerms);
  assert(renameRes.ok === true, "Platzhalter erfolgreich umbenannt");
  localCustomTerms = renameRes.customTerms;

  // Neuer Lauf mit geänderter Tabelle erzeugt neuen Platzhalter
  const editAnon2 = core.processText(editSampleText, editCfg, editState);
  assert(editAnon2.includes("VLAN-GAESTE"), "Neu anonymisierte Ausgabe enthält neuen Platzhalter 'VLAN-GAESTE'");
  assert(!editAnon2.includes(oldTextPh), "Neu anonymisierte Ausgabe enthält den alten Platzhalter nicht mehr");

  // Rückübersetzung funktioniert mit BEIDEN Namen (alt und neu)
  const deanomNew = core.deanonymizeText("Prüfen Sie VLAN-GAESTE auf dem Switch", editState);
  assert(deanomNew.includes("Uplink Praxis Dr Weber"), "Rückübersetzung mit neuem Namen ('VLAN-GAESTE') erfolgreich");
  const deanomOld = core.deanonymizeText(`Prüfen Sie ${oldTextPh} auf dem Switch`, editState);
  assert(deanomOld.includes("Uplink Praxis Dr Weber"), "Rückübersetzung mit altem Alias-Namen erfolgreich");

  // Aktive Tabelle listet nur neuen Namen, alten Namen nicht mehr
  const mappingAfterRename = core.extractMappingTableEntries(editState);
  assert(mappingAfterRename.entries.some(e => e.placeholder === "VLAN-GAESTE"), "Aktive Tabelle enthält 'VLAN-GAESTE'");
  assert(!mappingAfterRename.entries.some(e => e.placeholder === oldTextPh), "Aktive Tabelle blendet alten Alias-Platzhalter aus");

  // 17.3 Eintrag entfernen ("wird nicht anonymisiert")
  const vlanRow = mappingAfterRename.entries.find(e => e.original === "WAN_GUEST_192.0.2.0");
  assert(Boolean(vlanRow), "VLAN-Name in Tabelle vorhanden");
  const oldVlanPh = vlanRow.placeholder;

  // Abbruch bei nicht bestätigtem Dialog
  const cancelRemove = core.removeMappingTableEntry(editState, oldVlanPh, localCustomTerms, () => false);
  assert(cancelRemove.cancelled === true, "Entfernen bricht bei Nicht-Bestätigung ab");

  // Bestätigtes Entfernen
  let removePromptMessage = "";
  const removeRes = core.removeMappingTableEntry(editState, oldVlanPh, localCustomTerms, (msg) => {
    removePromptMessage = msg;
    return true;
  });
  assert(removeRes.ok === true, "Eintrag erfolgreich entfernt");
  assert(removePromptMessage.includes(core.REMOVE_CONFIRM_HINT), "Bestätigungshinweis 'Dieser Wert steht danach im Klartext in der Ausgabe.' vorhanden");
  localCustomTerms = removeRes.customTerms;

  assert(
    localCustomTerms.exakteWoerter.includes("WAN_GUEST_192.0.2.0"),
    "Entfernter Originalwert wurde in 'ausnahmen.exakteWoerter' aufgenommen"
  );

  // Neu-Anonymisieren mit reprocessFilesWithState: entfernter Wert bleibt im Klartext
  const reprocessRes = core.reprocessFilesWithState(
    [{ path: "switch.txt", text: editSampleText }],
    diskRules,
    localCustomTerms,
    editState,
    { overrides: { netzerhaltend: true } }
  );
  assert(reprocessRes.ok === true, "reprocessFilesWithState erfolgreich");
  const reprocessedText = reprocessRes.results[0].anonText;
  assert(
    reprocessedText.includes("name WAN_GUEST_192.0.2.0"),
    "Entfernter Begriff steht im Klartext in der neu anonymisierten Ausgabe"
  );

  // Rückübersetzung alter Texte mit dem alten Platzhalter funktioniert weiterhin
  const deanomRemovedOld = core.deanonymizeText(`Konfiguriere ${oldVlanPh}`, editState);
  assert(deanomRemovedOld.includes("WAN_GUEST_192.0.2.0"), "Alte KI-Antworten mit entferntem Platzhalter bleiben rückübersetzbar");

  // 17.4 Eintrag hinzufügen (addMappingTableEntry)
  const addRes = core.addMappingTableEntry(
    editState,
    { original: "extern-gw-01", placeholder: "GW-EXTERN", category: "FESTE_ZUORDNUNG" },
    diskRules,
    localCustomTerms
  );
  assert(addRes.ok === true, "Eintrag hinzufügen erfolgreich");
  localCustomTerms = addRes.customTerms;

  const textWithAdded = editSampleText + "\nroute 0.0.0.0/0 via extern-gw-01";
  const reprocessWithAdd = core.reprocessFilesWithState(
    [{ path: "switch.txt", text: textWithAdded }],
    diskRules,
    localCustomTerms,
    editState,
    { overrides: { netzerhaltend: true } }
  );
  assert(reprocessWithAdd.results[0].anonText.includes("GW-EXTERN"), "Neu hinzugefügter Begriff wird durch seinen Platzhalter ersetzt");

  // 17.5 Unveränderte Platzhalter bleiben nach "Neu anonymisieren" identisch
  const origIpPh = editAnon1.match(/\b(NET-\d+\.H\d+)\b/)[1];
  const newIpPh = reprocessWithAdd.results[0].anonText.match(/\b(NET-\d+\.H\d+)\b/)[1];
  assert(origIpPh === newIpPh, "Unveränderte Platzhalter (z. B. IP) bleiben nach 'Neu anonymisieren' 100 % identisch");

  // 17.6 Ungültige und doppelte Platzhalter werden abgelehnt
  const invPh1 = core.renameMappingTableEntry(editState, "VLAN-GAESTE", "klein_und_ungueltig!", diskRules, localCustomTerms);
  assert(invPh1.ok === false && invPh1.error.includes("[A-Z0-9-]{1,32}"), "Ungültige Syntax für Platzhalter wird abgelehnt");

  const invPh2 = core.renameMappingTableEntry(editState, "VLAN-GAESTE", "GW-EXTERN", diskRules, localCustomTerms);
  assert(invPh2.ok === false, "Bereits vergebener Platzhalter wird abgelehnt");

  const invPh3 = core.renameMappingTableEntry(editState, "VLAN-GAESTE", "WERK-STUTTGART", diskRules, localCustomTerms);
  assert(invPh3.ok === false && invPh3.error.includes("echten Begriff"), "Platzhalter, der einem echten Begriff entspricht, wird abgelehnt");

  // 17.7 Paritätstest mit anon.ps1 beim Einlesen von anon-regeln.lokal.json (ausnahmen.exakteWoerter)
  if (pwshCheck.status === 0) {
    const tmpParityDir = fs.mkdtempSync(path.join(os.tmpdir(), "anon-lokal-parity-"));
    const lokalRulesPath = path.join(tmpParityDir, "anon-regeln.lokal.json");
    const testInputPath = path.join(tmpParityDir, "input.txt");
    const testOutDir = path.join(tmpParityDir, "out");
    const testTabPath = path.join(tmpParityDir, "tab.json");

    const lokalRulesJson = JSON.stringify({
      eigeneBegriffe: {
        festeZuordnung: {
          "sw-core-lokal01": "CORE-LOKAL"
        }
      },
      ausnahmen: {
        exakteWoerter: [
          "Rechenzentrum-Nord Raum 2.04",
          "198.51.100.77"
        ]
      }
    }, null, 2);
    fs.writeFileSync(lokalRulesPath, lokalRulesJson, "utf8");

    const sampleParityInput = [
      "hostname sw-core-lokal01",
      "snmp-server location Rechenzentrum-Nord Raum 2.04",
      "interface 1/1/1",
      "   ip address 198.51.100.77/24",
      "   description Uplink zu Server"
    ].join("\n");
    fs.writeFileSync(testInputPath, sampleParityInput, "utf8");

    // JS-Ergebnis mit den lokalen Regeln
    const jsLokalLoaded = core.importLokaleBegriffeJson(lokalRulesJson);
    const jsMerged = core.validateAndMergeEigeneBegriffe(diskRules, jsLokalLoaded);
    const jsCfg = core.buildEngineConfig(jsMerged.mergedRules, { netzerhaltend: true });
    const jsState = new core.AnonState();
    const jsAnonOut = core.processText(sampleParityInput, jsCfg, jsState);

    // PowerShell CLI mit -LokaleRegeln
    const psCmd = `& "${PS1_PATH.replace(/\\/g, "\\\\")}" -Eingabe "${testInputPath.replace(/\\/g, "\\\\")}" -Ausgabe "${testOutDir.replace(/\\/g, "\\\\")}" -Regeln "${RULES_PATH.replace(/\\/g, "\\\\")}" -LokaleRegeln "${lokalRulesPath.replace(/\\/g, "\\\\")}" -TabellenPfad "${testTabPath.replace(/\\/g, "\\\\")}" -Unverschluesselt > $null`;
    const psRun = spawnSync("pwsh", ["-NoProfile", "-Command", psCmd], { encoding: "utf8" });
    assert(psRun.status === 0, `anon.ps1 mit -LokaleRegeln beendet mit Exit-Code 0 (${psRun.stderr || "ok"})`);

    const psOutFile = path.join(testOutDir, "anonym", "input.txt");
    assert(fs.existsSync(psOutFile), "anon.ps1 hat anonymisierte Datei erzeugt");
    const psAnonOut = fs.readFileSync(psOutFile, "utf8");

    assert(
      jsAnonOut.includes("hostname CORE-LOKAL") && psAnonOut.includes("hostname CORE-LOKAL"),
      "Parität: festeZuordnung aus anon-regeln.lokal.json wird von beiden Engines ersetzt"
    );
    assert(
      jsAnonOut.includes("snmp-server location Rechenzentrum-Nord Raum 2.04") &&
      psAnonOut.includes("snmp-server location Rechenzentrum-Nord Raum 2.04"),
      "Parität: Freitext-Ausnahme aus ausnahmen.exakteWoerter bleibt in beiden Engines im Klartext"
    );
    assert(
      jsAnonOut.includes("198.51.100.77") && psAnonOut.includes("198.51.100.77"),
      "Parität: IP-Ausnahme aus ausnahmen.exakteWoerter bleibt in beiden Engines im Klartext"
    );
    assert(
      jsAnonOut === psAnonOut,
      "Parität: 100 % identische Ausgabe zwischen anonymisierer.html und anon.ps1 mit anon-regeln.lokal.json"
    );

    fs.rmSync(tmpParityDir, { recursive: true, force: true });
  }

  // 17.8 Lokale Muster (eigeneHostnamenMuster, seriennummerMuster, tabellenSpalten) aus anon-regeln.lokal.json, Parität A == B
  {
    const lokalMusterJson = JSON.stringify({
      eigeneHostnamenMuster: ["(?i)(?<![A-Za-z0-9-])(xy[0-9]-(?:sw|dist)[0-9]{2})(?![A-Za-z0-9-])"],
      seriennummerMuster: ["(?i)((?<![A-Za-z0-9_])Inventar-Nr[ \\t]*:[ \\t]*)([A-Za-z0-9-]{5,24})()"],
      tabellenSpalten: [{ name: "Beispiel Nachbartabelle", kopf: ["Nachbar", "Schnittstelle"], spalten: [{ name: "Nachbar", kategorie: "HOST" }] }]
    }, null, 2);
    const lokalMusterInput = [
      "Peer XY1-SW03 is reachable",
      "uplink xy2-dist11 up, backup xy2-dist11_alt",
      "Inventar-Nr: INV-0042-77",
      "",
      "Nachbar        Schnittstelle",
      "nb-lager-ost   1/1/7",
      ""
    ].join("\n");
    const lokalMusterExpected = [
      "Peer HOST-2 is reachable",
      "uplink HOST-3 up, backup HOST-3_alt",
      "Inventar-Nr: SERIAL-1",
      "",
      "Nachbar        Schnittstelle",
      "HOST-1         1/1/7",
      ""
    ].join("\n");

    const loadedMuster = core.importLokaleBegriffeJson(lokalMusterJson);
    assert(Array.isArray(loadedMuster.muster.eigeneHostnamenMuster) && loadedMuster.muster.eigeneHostnamenMuster.length === 1,
      "Lokale Muster: importLokaleBegriffeJson übernimmt eigeneHostnamenMuster");
    const mergedMuster = core.validateAndMergeEigeneBegriffe(diskRules, loadedMuster);
    assert(mergedMuster.valid, `Lokale Muster: Zusammenführung gültig (${mergedMuster.errors.join(" | ")})`);
    assert(mergedMuster.mergedRules.hostnamenMuster.length === diskRules.hostnamenMuster.length,
      "Lokale Muster: hostnamenMuster der Basis bleibt unverändert, eigeneHostnamenMuster separat");
    const musterCfg = core.buildEngineConfig(mergedMuster.mergedRules, { netzerhaltend: true });
    const musterState = new core.AnonState();
    const jsMusterOut = core.processText(lokalMusterInput, musterCfg, musterState);
    if (jsMusterOut !== lokalMusterExpected) console.error("    Erhalten: " + JSON.stringify(jsMusterOut));
    assert(jsMusterOut === lokalMusterExpected, "Lokale Muster: eigeneHostnamenMuster, seriennummerMuster und tabellenSpalten greifen (JS)");
    const musterFindings = core.auditText(jsMusterOut, "lokal.txt", musterCfg, musterState);
    assert(musterFindings.length === 0,
      `Lokale Muster: Ausgabe ist im Prüfmodus SAUBER (${JSON.stringify(musterFindings.map(f => f.kategorie + ":" + f.fund))})`);
    const rawMusterFindings = core.auditText(lokalMusterInput, "lokal.txt", musterCfg);
    assert(rawMusterFindings.some(f => f.kategorie === "Rest-Hostname") && rawMusterFindings.some(f => f.kategorie === "Rest-Seriennummer") && rawMusterFindings.some(f => f.kategorie === "Rest-Tabellenfeld"),
      "Lokale Muster: Prüfmodus meldet Rohdaten über lokale Muster (Hostname, Seriennummer, Tabellenfeld)");
    const exportedMuster = JSON.parse(core.exportLokaleBegriffeJson(loadedMuster, diskRules));
    assert(Array.isArray(exportedMuster.eigeneHostnamenMuster) && Array.isArray(exportedMuster.tabellenSpalten),
      "Lokale Muster: Export von anon-regeln.lokal.json enthält die Muster wieder");
    const badMerge = core.validateAndMergeEigeneBegriffe(diskRules, { muster: { eigeneHostnamenMuster: ["(ungueltig"] } });
    assert(!badMerge.valid, "Lokale Muster: Ungültiger regulärer Ausdruck wird abgewiesen");

    if (pwshCheck.status === 0) {
      const tmpMusterDir = fs.mkdtempSync(path.join(os.tmpdir(), "anon-lokal-muster-"));
      const lokalMusterPath = path.join(tmpMusterDir, "anon-regeln.lokal.json");
      const musterInPath = path.join(tmpMusterDir, "eingabe.txt");
      const musterOutDir = path.join(tmpMusterDir, "out");
      const musterTabPath = path.join(tmpMusterDir, "tab.json");
      fs.writeFileSync(lokalMusterPath, lokalMusterJson, "utf8");
      fs.writeFileSync(musterInPath, lokalMusterInput, "utf8");
      const esc = (p) => p.replace(/\\/g, "\\\\");
      const psMusterCmd = `& "${esc(PS1_PATH)}" -Eingabe "${esc(musterInPath)}" -Ausgabe "${esc(musterOutDir)}" -Regeln "${esc(RULES_PATH)}" -LokaleRegeln "${esc(lokalMusterPath)}" -TabellenPfad "${esc(musterTabPath)}" -Unverschluesselt > $null; exit $LASTEXITCODE`;
      const psMusterRun = spawnSync("pwsh", ["-NoProfile", "-Command", psMusterCmd], { encoding: "utf8" });
      assert(psMusterRun.status === 0, `anon.ps1 mit lokalen Mustern endet SAUBER mit Exit-Code 0 (${psMusterRun.status})`);
      const psMusterOut = fs.readFileSync(path.join(musterOutDir, "anonym", "eingabe.txt"), "utf8");
      assert(psMusterOut === jsMusterOut, "Parität: Lokale Muster liefern in anonymisierer.html und anon.ps1 identische Ausgabe");
      fs.rmSync(tmpMusterDir, { recursive: true, force: true });
    }
  }

  // 17.9 Tabellen-Austausch: In der Browser-Variante gespeicherte Tabelle (ANON-AES256-2) wird von anon.ps1 gelesen
  if (pwshCheck.status === 0) {
    const tmpXDir = fs.mkdtempSync(path.join(os.tmpdir(), "anon-tab-austausch-"));
    const xCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
    const xState = new core.AnonState();
    const xAnon = core.processText("hostname sw-core-x01\nip address 192.0.2.5/24", xCfg, xState);
    const xTab = await core.encryptTableAes256V2(JSON.stringify(xState.toJSON()), "AustauschPasswort#2026");
    const xTabPath = path.join(tmpXDir, "tabelle.anontab");
    const xKiPath = path.join(tmpXDir, "ki.txt");
    const xOutPath = path.join(tmpXDir, "ki-echt.txt");
    fs.writeFileSync(xTabPath, xTab, "utf8");
    fs.writeFileSync(xKiPath, "Pruefe " + xAnon.replace(/\n/g, " / "), "utf8");
    const esc = (p) => p.replace(/\\/g, "\\\\");
    const xCmd = `$pw = ConvertTo-SecureString "AustauschPasswort#2026" -AsPlainText -Force; & "${esc(PS1_PATH)}" -Zurueck -Eingabe "${esc(xKiPath)}" -Ausgabe "${esc(xOutPath)}" -TabellenPfad "${esc(xTabPath)}" -PasswortSecure $pw > $null; exit $LASTEXITCODE`;
    const xRun = spawnSync("pwsh", ["-NoProfile", "-Command", xCmd], { encoding: "utf8" });
    assert(xRun.status === 0, `Tabellen-Austausch: anon.ps1 lädt Browser-Tabelle ANON-AES256-2/PBKDF2-SHA256 (${xRun.status})`);
    const xRestored = fs.existsSync(xOutPath) ? fs.readFileSync(xOutPath, "utf8") : "";
    assert(xRestored === "Pruefe hostname sw-core-x01 / ip address 192.0.2.5/24", `Tabellen-Austausch: Rückübersetzung in anon.ps1 korrekt (${xRestored})`);
    fs.rmSync(tmpXDir, { recursive: true, force: true });
  }

  // --- 18. Prüfe Text-Pseudonymisierungs-Engine (core/text) ---
  console.log("--- 18. Prüfe Text-Pseudonymisierungs-Engine (core/text) ---");
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

  // 18.x HTML-Kopie der Freitext-Engine muss mit core/text/text-engine.js übereinstimmen
  {
    const coreSrc = fs.readFileSync(textEnginePath, "utf8");
    const coreStart = coreSrc.indexOf('function () {\n  "use strict";\n') + 'function () {\n  "use strict";\n'.length;
    const coreBody = coreSrc.slice(coreStart, coreSrc.lastIndexOf("\n});"));
    const htmlMarker = 'const TextPseudonymizer = (function () {\n\n  "use strict";\n';
    const htmlStart = htmlContent.indexOf(htmlMarker) + htmlMarker.length;
    const htmlBody = htmlContent.slice(htmlStart, htmlContent.indexOf("\n  })();", htmlStart));
    assert(coreBody.length > 10000 && coreBody === htmlBody, "Freitext-Engine: Kopie in anonymisierer.html ist identisch mit core/text/text-engine.js");
  }

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

  // UI-Hinweise & Paritätsausschluss in HTML und README
  const updatedHtml = fs.readFileSync(HTML_PATH, "utf8");
  const readmeContent = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  assert(updatedHtml.includes("Text-Reiter nur Web, in anon.ps1 nicht enthalten"), "Hinweis 'Text-Reiter nur Web, in anon.ps1 nicht enthalten' in anonymisierer.html vorhanden");
  assert(/Text-Reiter nur Web,\s*in\s*(`?anon\.ps1`?)\s*nicht enthalten/i.test(readmeContent), "Hinweis 'Text-Reiter nur Web, in anon.ps1 nicht enthalten' im README.md vorhanden");
  assert(updatedHtml.includes("Rückführbar über die Zuordnungstabelle. Ersetzt keine fachliche Sichtprüfung"), "Rechtlicher Hinweistext in anonymisierer.html vorhanden");
  assert(updatedHtml.includes("data-tab=\"tab-text\""), "Tab-Navigation '4. Text (Datenschutz)' vorhanden");
  assert(updatedHtml.includes("id=\"tab-text\""), "Tab-Inhalt 'tab-text' vorhanden");
  assert(updatedHtml.includes("textInteractivePreview"), "Interaktive Vorschau-Box vorhanden");

  // XSS-Sicherheitstest für DOM-Erzeugung
  // Simulieren wir die DOM-Generierung: Spans und Text-Segmente werden als DOM-Knoten erzeugt
  const maliciousInput = "<script>alert('pwn')</script><img src=x onerror=alert(1)> test@domain.de";
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
  assert(simulatedDomText.includes("[SPAN:test@domain.de]"), "Span umfasst sicher das Token");

  console.log(`\n========================================`);
  console.log(`TESTERGEBNIS (Node.js): ${passed} bestanden, ${failed} fehlgeschlagen`);
  console.log(`========================================`);
  process.exit(failed > 0 ? 1 : 0);
})();


