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
const HTML_PATH = path.join(ROOT, "web", "anonymisierer.html");
const PS1_PATH = path.join(ROOT, "powershell", "anon.ps1");
const RULES_PATH = path.join(ROOT, "regeln", "anon-regeln.json");
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
  add("benutzerMusterSchwach", rules.benutzerMusterSchwach);
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

  // 3a. LF-Lauf (optional mit zusätzlicher festeZuordnung des Testfalls)
  let caseRules = diskRules;
  if (tc.festeZuordnung) {
    caseRules = JSON.parse(JSON.stringify(diskRules));
    Object.assign(caseRules.eigeneBegriffe.festeZuordnung, tc.festeZuordnung);
  }
  const cfg = core.buildEngineConfig(caseRules, overrides);
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

  // Eine Zuordnungstabelle enthält nie interne Schutz-Marker (sonst ist die Rückübersetzung kaputt)
  const tabWerte = [].concat(...Object.values(state.toJSON()).filter(v => v && typeof v === "object").map(v => Object.entries(v).flat())).join("\n");
  assert(!/[\u0002\u0003]/.test(tabWerte), `${tc.id}: Zuordnungstabelle enthält keine Schutz-Marker`);
  if (Array.isArray(tc.tabelleEnthaeltNicht)) {
    const tabJson = JSON.stringify(state.toJSON());
    for (const geheim of tc.tabelleEnthaeltNicht) {
      assert(!tabJson.includes(geheim) && !actual.includes(geheim), `${tc.id}: '${geheim}' steht weder in der Ausgabe noch in der Zuordnungstabelle`);
    }
  }

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
  assert(findings.length === 0, `Beispieldatei ${sf} ist nach Anonymisierung ohne Restfunde (0 Restfunde)`);

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
const origRelPath = "Rechenzentrum-Nord/dc1-sw-core01/show-tech-acc-halle2-01_192.0.2.1.txt";
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
    assert(bomFindings.length === 0, `Befund 3: Anonymisiertes ${label}-Eventlog ist ohne Restfunde`);
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
    ps1Content.includes('if ($pruefStatus -eq "KEINE_RESTFUNDE")') && ps1Content.includes("exit 2"),
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
  const boundOut = core.processText("dc1-tor-01 und dc1-tor-010", boundCfg, boundState);
  assert(
    boundOut === "TOR-A und dc1-tor-010" && !boundOut.includes("TOR-A0"),
    `Befund 8: 'dc1-tor-01' macht 'dc1-tor-010' nicht zu 'TOR-A0' (Ergebnis: ${boundOut})`
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
    "hostname dc1-sw-core01",
    "Version : FL.10.13.1020",
    "snmp-server system-location Rechenzentrum-Nord Halle 3",
    "snmp-server system-contact Max Mustermann (netze@intern.example.invalid)",
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
      `2026-10-16T14:22:${(i % 59).toString().padStart(2, "0")}.123Z dc1-sw-core01 hpe-routing[${i}]: Event on sn link state up for ${net}.${o4}`
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
  assert(largeFindings.length === 0, `Großer Aruba Show-Tech ist nach Anonymisierung ohne Restfunde (0 Restfunde)`);
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
    "MikroTik Interface-/VLAN-/Bridge-Namen (name= und interface= konsistent)": "/interface vlan add interface=bridge1 name=\"Kunde Mustermann Ethernet1/1/1\" vlan-id=10",
    "Port-Name / Display-String (Ruckus ICX port-name, Extreme EXOS display-string)": " port-name Kunde Mustermann Ethernet1/1/1"
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

  // Wirkung auf Anonymisierung + Prüfung (ohne Restfunde)
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
  assert(customAudit.length === 0, "Eigene Begriffe Wirkung: Anonymisierter Text mit eigenen Begriffen und Auto-Platzhalter ist im Prüfmodus ohne Restfunde");

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
  const copyLargeOriginal = "hostname dc1-sw-core01\n" + "X".repeat(250 * 1024); // > 200 KB
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

  // Anonymisiert kopieren (ohne Restfunde, > 200 KB): kopiert sofort ohne Warn-Dialog den ungekürzten Text
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
    "Kopierfunktion Anonymisiert (ohne Restfunde, > 200 KB): Liefert ungekürzten Inhalt ohne Warnabfrage inkl. KB-Hinweis"
  );

  // Anonymisiert kopieren (mit Restfunden): gesperrt, auch eine Bestätigung hebt die Sperre nicht auf
  let dirtyPromptCalled = false;
  const anonDirtyBlocked = core.preparePreviewCopy(mockProcessedResults, 1, "anon", () => { dirtyPromptCalled = true; return true; });
  assert(anonDirtyBlocked.allowed === false && anonDirtyBlocked.reason === "RESTFUNDE" && !dirtyPromptCalled,
    "Kopierfunktion Anonymisiert (mit Restfunden): gesperrt, keine Bestätigung möglich");
  const anonLaufGesperrt = core.preparePreviewCopy(mockProcessedResults, 0, "anon", () => true, { freigegeben: false });
  assert(anonLaufGesperrt.allowed === false && anonLaufGesperrt.reason === "RESTFUNDE",
    "Kopierfunktion Anonymisiert: gesperrt, solange der Lauf insgesamt mit Restfunden ist (auch für saubere Einzeldatei)");

  // 16.3b Restfunde: Gruppen entscheiden ("immer ersetzen" / "Fehlalarm"), Freigabe erst bei ohne Restfunde
  {
    const gFiles = [{ path: "probe.txt", text: "hostname edge7\nlink edge7-alt\nstatus edge7-alt ok\nkommentar Q-Wert-77\n" }];
    const gState = new core.AnonState();
    const lauf1 = core.reprocessFilesWithState(gFiles, diskRules, {}, gState, { overrides: { netzerhaltend: true } });
    const gruppen = core.groupAuditFindings(lauf1.findings);
    assert(lauf1.findings.length >= 2 && gruppen.length === 1 && gruppen[0].anzahl === lauf1.findings.length,
      `Fundgruppen: gleiche Kategorie und gleicher Wert bilden eine Gruppe (${lauf1.findings.length} Funde, ${gruppen.length} Gruppe)`);
    assert(!core.isReleaseAllowed(lauf1.findings, false, lauf1.results), "Freigabe: bei RESTFUNDE gesperrt");
    assert(!core.allGroupsDecided(gruppen, {}), "Fundgruppen: ohne Entscheidung nicht vollständig");

    const ersetzt = core.applyFindingDecisions({}, gruppen, { [gruppen[0].schluessel]: "ersetzen" });
    assert(ersetzt.festeZuordnung.some(r => r.original === "edge7-alt" && r.placeholder === "") && !ersetzt.festeZuordnung.some(r => r.original === "edge7"),
      `Entscheidung 'immer ersetzen': ganzes Wort an der Fundstelle als eigener Begriff mit automatischem Platzhalter (${JSON.stringify(ersetzt.festeZuordnung)})`);
    const lauf2 = core.reprocessFilesWithState(gFiles, diskRules, ersetzt, new core.AnonState(), { overrides: { netzerhaltend: true } });
    assert(lauf2.ok && lauf2.findings.length === 0 && !lauf2.results[0].anonText.includes("edge7") && core.isReleaseAllowed(lauf2.findings, false, lauf2.results),
      "Nach 'immer ersetzen' und neuem Lauf: ohne Restfunde und freigegeben");

    const fehlalarm = core.applyFindingDecisions({}, gruppen, { [gruppen[0].schluessel]: "fehlalarm" });
    assert(fehlalarm.exakteWoerter.includes("edge7-alt") && !fehlalarm.exakteWoerter.includes("edge7"), "Entscheidung 'Fehlalarm': das Wort an der Fundstelle wird Ausnahme, nicht der Hostname selbst");
    const lauf3 = core.reprocessFilesWithState(gFiles, diskRules, fehlalarm, new core.AnonState(), { overrides: { netzerhaltend: true } });
    assert(lauf3.ok && lauf3.findings.length === 0 && lauf3.results[0].anonText.startsWith("hostname HOST-1"), "Nach 'Fehlalarm' und neuem Lauf: ohne Restfunde, der Hostname bleibt ersetzt");
    assert(!core.isReleaseAllowed([], true, lauf3.results), "Freigabe: Trockenlauf gibt nie frei");

    const exportHandler = htmlContent.slice(htmlContent.indexOf("function updateReleaseUI()"), htmlContent.indexOf('getElementById("btnDownloadReport").addEventListener'));
    const exportFreiFn = htmlContent.slice(htmlContent.indexOf("function exportFrei()"), htmlContent.indexOf("function exportFrei()") + 120);
    assert(exportHandler.includes("const frei = releaseAllowed && !st.gesperrt;") && exportHandler.includes('getElementById("btnDownloadZip").disabled = !frei') && exportHandler.includes('getElementById("btnCopyAnon").disabled = !frei') &&
      exportHandler.includes("if (!exportFrei())") && exportFreiFn.includes("return releaseAllowed && !ablaufStatusJetzt().gesperrt;"),
      "UI: ZIP-Download und 'Anonymisiert kopieren' hängen an releaseAllowed und am Ablaufstatus (nur ohne Restfunde und vollständig)");
  }

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
    "hostname dc1-sw-core01",
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
      `Lokale Muster: Ausgabe ist im Prüfmodus ohne Restfunde (${JSON.stringify(musterFindings.map(f => f.kategorie + ":" + f.fund))})`);
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
      assert(psMusterRun.status === 0, `anon.ps1 mit lokalen Mustern endet ohne Restfunde mit Exit-Code 0 (${psMusterRun.status})`);
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

  // --- 20. Paket A: gezielte Regressionstests (Pfade, Kollisionen, Bezeichnung) ---
  console.log("--- 20. Paket A: Pfade, Platzhalter-Kollisionen, Bezeichnung ---");
  {
    // A4: bekannte Originalwerte in Dateinamen auch an "-", "_" und "." grenzend
    const pfadFiles = [
      { path: "privatehost01-backup.txt", text: "hostname privatehost01\n" },
      { path: "logs/privatehost01.old.log", text: "uptime 3 days\n" }
    ];
    const pfadLauf = core.reprocessFilesWithState(pfadFiles, diskRules, {}, new core.AnonState(), { overrides: { netzerhaltend: true } });
    const pfade = pfadLauf.results.map(r => r.path);
    assert(pfade[0] === "HOST-1-backup.txt" && pfade[1] === "logs/HOST-1.old.log", `A4: bekannter Host im Dateinamen an '-' und '.' ersetzt (${pfade.join(", ")})`);
    const pfadState = new core.AnonState();
    core.reprocessFilesWithState([pfadFiles[0]], diskRules, {}, pfadState, { overrides: { netzerhaltend: true } });
    const pfadAudit = core.auditText("uptime 3 days", "privatehost01-backup.txt", core.buildEngineConfig(diskRules, {}), pfadState);
    assert(pfadAudit.some(f => f.kategorie === "Pfad-Bekannt"), `A4: Prüfmodus meldet bekannte Originalwerte im Dateipfad (${JSON.stringify(pfadAudit.map(f => f.kategorie))})`);

    // A5: Eindeutigkeit beim Laden einer Tabelle
    if (typeof core.findPlaceholderCollisions !== "function") {
      assert(false, "A5: findPlaceholderCollisions fehlt (Eindeutigkeitsprüfung der Platzhalter)");
    } else {
    const kollState = core.AnonState.fromJSON({ vorwaerts: { "host|device-x": "HOST-1" }, rueckwaerts: { "HOST-1": "device-x" }, zaehler: { HOST: 1 } });
    const kollisionen = core.findPlaceholderCollisions(kollState, { "device-one": "HOST-1" });
    assert(kollisionen.length === 1 && kollisionen[0].indexOf("HOST-1") >= 0, `A5: Tabelle mit HOST-1 = device-x und festeZuordnung device-one -> HOST-1 wird als Kollision erkannt (${kollisionen.join(" | ")})`);
    const doppelt = core.AnonState.fromJSON({ vorwaerts: { "host|a-1": "HOST-1", "host|b-1": "HOST-1" }, rueckwaerts: { "HOST-1": "a-1" } });
    assert(core.findPlaceholderCollisions(doppelt, {}).length === 1, "A5: zwei Originalwerte mit demselben Platzhalter in einer Tabelle werden erkannt");
    assert(core.findPlaceholderCollisions(core.AnonState.fromJSON({ vorwaerts: { "host|a-1": "HOST-1" }, rueckwaerts: { "HOST-1": "a-1" } }), { "a-1": "HOST-1" }).length === 0, "A5: identische Zuordnung ist keine Kollision");
    const ladeHandler = htmlContent.slice(htmlContent.indexOf('getElementById("inputTableFile").addEventListener'), htmlContent.indexOf('getElementById("btnResetTableState")'));
    assert(ladeHandler.includes("validateImportedTable("), "A5: anonymisierer.html prüft beim Laden einer Tabelle die Eindeutigkeit der Platzhalter (validateImportedTable)");
    const koll5 = core.validateImportedTable({ version: "1.0", vorwaerts: { "host|device-x": "HOST-1" }, rueckwaerts: { "HOST-1": "device-x" } }, { "device-one": "HOST-1" });
    assert(!koll5.ok, "A5: validateImportedTable lehnt Kollision mit festeZuordnung ab");
    }

    // A9: Bezeichnung "Keine Restfunde nach aktivem Regelwerk" statt "SAUBER"
    assert(!/SAUBER/.test(htmlContent), "A9: anonymisierer.html verwendet die Bezeichnung 'SAUBER' nicht mehr");
    assert(htmlContent.includes("Keine Restfunde nach aktivem Regelwerk") && htmlContent.includes('"KEINE_RESTFUNDE"'), "A9: anonymisierer.html meldet 'Keine Restfunde nach aktivem Regelwerk' (Bericht: KEINE_RESTFUNDE)");
    const readmeA9 = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
    assert(readmeA9.includes("Keine Restfunde nach aktivem Regelwerk") && readmeA9.includes("KEINE_RESTFUNDE"), "A9: README erklärt 'Keine Restfunde nach aktivem Regelwerk' / KEINE_RESTFUNDE");
  }

  // --- 21. Paket B: Teilmaskierung, Exportfreigabe, Pfadkollisionen, Tabellenimport ---
  console.log("--- 21. Paket B: Teilmaskierung, Exportfreigabe, Pfadkollisionen, Tabellenimport ---");
  {
    const bCfg = core.buildEngineConfig(diskRules, {});
    // B1: Prüfmodus erkennt teilweise maskierte Werte
    for (const teil of ['password "***** BetaSecret77"', "password '***** BetaSecret77'", "secret Rest42*****", "https://alice:*****x@host.example.invalid/"]) {
      const fundeTeil = core.auditText(teil, "x", bCfg);
      assert(fundeTeil.length > 0, `B1: Prüfmodus meldet teilweise maskierten Wert (${teil.replace(/[A-Za-z]+[0-9]+/g, "…")}): ${JSON.stringify(fundeTeil.map(f => f.kategorie))}`);
    }

    // B3: Exportfreigabe als Zustandsautomat; jede relevante Änderung macht das Ergebnis ungültig
    if (typeof core.createReleaseGuard !== "function") {
      assert(false, "B3: createReleaseGuard fehlt (zentrale Exportfreigabe)");
    } else {
      const g = core.createReleaseGuard();
      assert(!g.isAllowed(), "B3: ohne Lauf keine Freigabe");
      let lauf = g.startRun();
      g.finishRun(lauf, { findings: [], isProbe: false, resultCount: 1 });
      assert(g.isAllowed(), "B3: Lauf ohne Restfunde gibt frei");
      for (const grund of ["dateien", "regeln", "eigeneBegriffe", "optionen", "tabelleGeaendert", "tabelleZurueckgesetzt", "tabelleGeladen"]) {
        lauf = g.startRun();
        g.finishRun(lauf, { findings: [], isProbe: false, resultCount: 1 });
        g.markChanged(grund);
        assert(!g.isAllowed() && g.reason() === grund, `B3: Änderung '${grund}' macht die Freigabe ungültig`);
      }
      const alt = g.startRun();
      g.markChanged("dateien");
      g.finishRun(alt, { findings: [], isProbe: false, resultCount: 1 });
      assert(!g.isAllowed(), "B3: Lauf, während dessen sich die Eingabe geändert hat, gibt nicht frei");
      lauf = g.startRun();
      g.finishRun(lauf, { findings: [{ kategorie: "Rest-IPv4" }], isProbe: false, resultCount: 1 });
      assert(!g.isAllowed(), "B3: Lauf mit Restfunden gibt nicht frei");
      lauf = g.startRun();
      g.finishRun(lauf, { findings: [], isProbe: true, resultCount: 1 });
      assert(!g.isAllowed(), "B3: Trockenlauf gibt nicht frei");
    }

    // B4: Ausgabepfade müssen eindeutig sein (Windows: ohne Groß-/Kleinschreibung)
    if (typeof core.findPathCollisions !== "function") {
      assert(false, "B4: findPathCollisions fehlt");
    } else {
      assert(core.findPathCollisions(["a/HOST-1.txt", "a/host-1.txt", "b.txt"]).length === 1, "B4: gleiche Ausgabepfade (Groß-/Kleinschreibung) werden erkannt");
      assert(core.findPathCollisions(["a.txt", "b.txt"]).length === 0, "B4: verschiedene Pfade sind keine Kollision");
    }
    const kollFiles = [{ path: "x/privatehost01.txt", text: "hostname privatehost01\n" }, { path: "x/HOST-1.txt", text: "uptime\n" }];
    const kollLauf = core.reprocessFilesWithState(kollFiles, diskRules, {}, new core.AnonState(), { overrides: { netzerhaltend: true } });
    assert(kollLauf.ok === false && /Ausgabepfad/.test((kollLauf.errors || []).join(" ")), `B4: Lauf mit doppeltem Ausgabepfad wird abgebrochen (${JSON.stringify(kollLauf.errors)})`);
    let zipWirft = false;
    try { core.buildReleaseZipEntries([{ path: "a.txt", anonText: "1" }, { path: "A.txt", anonText: "2" }]); } catch (e) { zipWirft = true; }
    assert(zipWirft, "B4: ZIP mit doppelten Zielpfaden wird nicht erzeugt");

    // B5: Tabellenimport prüft Schema, Formatversion und beide Richtungen
    if (typeof core.validateImportedTable !== "function") {
      assert(false, "B5: validateImportedTable fehlt");
    } else {
      const v = (obj) => core.validateImportedTable(obj, {});
      assert(!v({ version: "1.0", vorwaerts: { "host|device-one": "HOST-1" }, rueckwaerts: { "HOST-1": "device-two" } }).ok, "B5: vorwaerts HOST|device-one -> HOST-1, rueckwaerts HOST-1 -> device-two wird abgelehnt");
      assert(!v({ version: "9.9", vorwaerts: {}, rueckwaerts: {} }).ok, "B5: unbekannte Formatversion wird abgelehnt");
      assert(!v({ version: "1.0", vorwaerts: {} }).ok, "B5: fehlendes rueckwaerts wird abgelehnt");
      assert(!v({ version: "1.0", vorwaerts: { "host|a-1": 5 }, rueckwaerts: { "HOST-1": "a-1" } }).ok, "B5: nicht-textuelle Werte werden abgelehnt");
      assert(!v({ version: "1.0", vorwaerts: { "host|a-1": "HOST-1" }, rueckwaerts: {} }).ok, "B5: Platzhalter ohne Rückrichtung wird abgelehnt");
      assert(!v([1, 2]).ok && !v(null).ok, "B5: kein Objekt wird abgelehnt");
      assert(v({ version: "1.0", vorwaerts: { "mac|0a1b2c3d4e5f": "MAC-1" }, rueckwaerts: { "MAC-1": "0a:1b:2c:3d:4e:5f" } }).ok, "B5: zulässige Normalisierung (MAC) wird akzeptiert");
      // Echte Tabelle aus einem Lauf inkl. umbenanntem Platzhalter (Alias) muss akzeptiert werden
      const echt = new core.AnonState();
      core.processText("hostname dc9-sw01\nip address 192.0.2.5/24\nmac 0a:1b:2c:3d:4e:5f\n description Halle", core.buildEngineConfig(diskRules, { netzerhaltend: true }), echt);
      assert(v(JSON.parse(JSON.stringify(echt.toJSON()))).ok, `B5: Tabelle aus einem echten Lauf wird akzeptiert (${v(JSON.parse(JSON.stringify(echt.toJSON()))).fehler.join(" | ")})`);
      const umbenannt = core.renameMappingTableEntry(echt, "HOST-1", "SW-NEU", diskRules, {});
      assert(umbenannt.ok !== false && v(JSON.parse(JSON.stringify(echt.toJSON()))).ok, "B5: Tabelle mit umbenanntem Platzhalter (Alias) wird akzeptiert");
      const ladeHandlerB5 = htmlContent.slice(htmlContent.indexOf('getElementById("inputTableFile").addEventListener'), htmlContent.indexOf('getElementById("btnResetTableState")'));
      assert(ladeHandlerB5.includes("validateImportedTable("), "B5: anonymisierer.html prüft importierte Tabellen vor dem Übernehmen");
    }
  }

  // --- 19. Strukturvorlage (Regelentwicklung ohne Echtdaten) ---
  console.log("--- 19. Prüfe Strukturvorlage ---");
  {
    const vorlageJson = JSON.parse(fs.readFileSync(path.join(ROOT, "regeln", "strukturvorlage.json"), "utf8"));
    assert(JSON.stringify(vorlageJson) === JSON.stringify(core.STRUKTUR_VORLAGE), "Strukturvorlage: Schlüsselwortliste in anonymisierer.html identisch mit regeln/strukturvorlage.json");
    const keywords = core.keywordSetFromVorlage(vorlageJson);
    const svCfg = core.buildEngineConfig(diskRules, {});
    // Buchstaben- und Ziffernfolgen wie die Vorlage sie trennt
    const tokens = (t) => {
      const out = [];
      for (const run of t.match(/[\p{L}0-9]+/gu) || []) {
        if (keywords.has(run.toLowerCase())) { out.push(run); continue; }
        for (const part of run.match(/[0-9]+|\p{L}+/gu) || []) out.push(part);
      }
      return out;
    };
    const formOnly = (t) => /^[Aa]+$|^9+$/.test(t);
    const pruefeVorlage = (label, input) => {
      const out = core.buildStructureTemplate(input, svCfg, keywords, vorlageJson.freitextPlatzhalter);
      const inputTokens = new Set(tokens(input).filter(t => !keywords.has(t.toLowerCase()) && !formOnly(t)));
      const leaked = tokens(out).filter(t => inputTokens.has(t) && t !== "FREITEXT");
      assert(leaked.length === 0, `Strukturvorlage ${label}: keine Buchstaben-/Ziffernfolge aus der Eingabe außer Schlüsselwörtern (${leaked.slice(0, 5).join(", ")})`);
      if (!/-----BEGIN /.test(input)) {
        assert(out.split(/\r?\n/).length === input.split(/\r?\n/).length, `Strukturvorlage ${label}: Zeilenzahl bleibt erhalten`);
      }
      return out;
    };
    const svInput = fs.readFileSync(path.join(__dirname, "beispiele-struktur.txt"), "utf8");
    for (const [label, eol] of [["LF", "\n"], ["CRLF", "\r\n"]]) {
      const out = pruefeVorlage("AOS-CX-Auszug " + label, svInput.replace(/\r?\n/g, eol));
      const lines = out.split(eol);
      assert(lines[0] === "hostname aa9-aaaa99", `Strukturvorlage ${label}: Schlüsselwort bleibt, Wert wird geformt (${lines[0]})`);
      assert(lines[1] === "interface 9/9/99" && lines[3] === "    ip address 999.9.9.99/99", `Strukturvorlage ${label}: Ports und IPs als 9-Form (${lines[1]} | ${lines[3]})`);
      assert(lines[2] === "    description <FREITEXT>" && lines[6] === "    name <FREITEXT>" && lines[10] === "banner motd ^<FREITEXT>^", `Strukturvorlage ${label}: Freitextfelder komplett <FREITEXT>`);
      assert(lines[7] === "snmp-server community *****" && lines[8].endsWith("password ciphertext *****"), `Strukturvorlage ${label}: Geheimnisse *****`);
      assert(lines[12].startsWith("LOCAL-PORT  CHASSIS-ID") && lines[12].endsWith("SYS-NAME"), `Strukturvorlage ${label}: Tabellenkopf bleibt erhalten`);
      assert(lines[14].includes("9a:9a:9a:9a:9a:99") && lines[14].includes("<FREITEXT>") && lines[14].endsWith("aa9-aaaa99"), `Strukturvorlage ${label}: Tabellenzeile geformt, Beschreibungsspalte <FREITEXT> (${lines[14]})`);
      assert(lines[16].startsWith('{"device_metadata": {"localhost": {"hostname": "aa9-leaf99", "mac": "9a:9a:9a:9a:9a:9a"}}}') && JSON.parse(lines[16]),
        `Strukturvorlage ${label}: JSON-Struktur und Schlüssel bleiben, Schlüsselwort 'leaf' bleibt stehen (${lines[16]})`);
    }
    const sortierteBeispiele = fs.readdirSync(BEISPIELE_DIR).filter(f => !f.startsWith(".")).sort();
    const jsVorlagen = sortierteBeispiele.map(f => pruefeVorlage(f, fs.readFileSync(path.join(BEISPIELE_DIR, f), "utf8")));
    assert(htmlContent.includes("Vor Weitergabe sichten!") && htmlContent.includes('id="btnStrukturvorlage"'), "Strukturvorlage: Button und Hinweis 'Vor Weitergabe sichten!' in anonymisierer.html");

    if (pwshCheck.status === 0) {
      const svDir = fs.mkdtempSync(path.join(os.tmpdir(), "anon-struktur-"));
      const esc = (p) => p.replace(/\\/g, "\\\\");
      const svCmd = `& "${esc(PS1_PATH)}" -Strukturvorlage -Eingabe "${esc(BEISPIELE_DIR)}" -Ausgabe "${esc(svDir)}" -Regeln "${esc(RULES_PATH)}"; exit $LASTEXITCODE`;
      const svRun = spawnSync("pwsh", ["-NoProfile", "-Command", svCmd], { encoding: "utf8" });
      assert(svRun.status === 0 && /Vor Weitergabe sichten/.test(svRun.stdout), `anon.ps1 -Strukturvorlage: Exit-Code 0 und Hinweis 'Vor Weitergabe sichten' (${svRun.status})`);
      sortierteBeispiele.forEach((f, i) => {
        const nr = String(i + 1).padStart(3, "0");
        const kandidaten = fs.readdirSync(svDir).filter(n => n.startsWith(`strukturvorlage-${nr}`));
        const psOut = kandidaten.length === 1 ? fs.readFileSync(path.join(svDir, kandidaten[0]), "utf8") : null;
        assert(psOut === jsVorlagen[i], `Parität Strukturvorlage: ${f} in anon.ps1 und anonymisierer.html identisch`);
      });
      fs.rmSync(svDir, { recursive: true, force: true });
    }
  }

  // Fund-Zeile "quelle|zeile|kategorie|fund" zerlegen (fund ist der Rest und darf "|" enthalten)
  function zerlegeFundZeile(z) {
    const t = String(z).split("|");
    return { quelle: t[0], zeile: t[1], kategorie: t[2], fund: t.slice(3).join("|") };
  }
  // Funde als Multimenge vergleichen (ordinal, Groß-/Kleinschreibung zählt, keine Deduplizierung).
  // Diagnosen enthalten nur Quelle, Kategorie, Zeile und Anzahl, nie Fundwerte.
  function vergleicheFundMultimengen(soll, ist) {
    const sep = "\u0000";
    const zaehle = (liste) => {
      const orte = new Map();
      for (const f of liste) {
        const ort = [f.quelle, String(f.zeile), f.kategorie].join(sep);
        if (!orte.has(ort)) orte.set(ort, new Map());
        const werte = orte.get(ort);
        werte.set(f.fund, (werte.get(f.fund) || 0) + 1);
      }
      return orte;
    };
    const a = zaehle(soll), b = zaehle(ist);
    const summe = (m) => Array.from(m.values()).reduce((x, y) => x + y, 0);
    const diagnosen = [];
    const orte = Array.from(new Set([...a.keys(), ...b.keys()])).sort();
    for (const ort of orte) {
      const [quelle, zeile, kategorie] = ort.split(sep);
      const wo = `${quelle} ${kategorie} Zeile ${zeile}`;
      const ma = a.get(ort), mb = b.get(ort);
      if (!mb) { diagnosen.push(`fehlend: ${wo}, Anzahl ${summe(ma)}`); continue; }
      if (!ma) { diagnosen.push(`zusätzlich: ${wo}, Anzahl ${summe(mb)}`); continue; }
      const werte = new Set([...ma.keys(), ...mb.keys()]);
      let gleich = true;
      for (const w of werte) if ((ma.get(w) || 0) !== (mb.get(w) || 0)) { gleich = false; break; }
      if (gleich) continue;
      const sa = summe(ma), sb = summe(mb);
      if (sa !== sb) diagnosen.push(`abweichende Häufigkeit: ${wo}, Soll ${sa}, Ist ${sb}`);
      else diagnosen.push(`gleicher Fundort, abweichender Inhalt: ${wo}, Anzahl ${sa}`);
    }
    return diagnosen;
  }

  // --- 22a. Selbsttest des Multimengenvergleichs ---
  console.log("--- 22a. Selbsttest des Multimengenvergleichs ---");
  {
    const basis = ["K1/a.txt|1|Nachpruefung-Benutzer|wertA", "K1/a.txt|1|Nachpruefung-Benutzer|wertA", "K1/a.txt|2|Nachpruefung-Geheimnis|wertB", "K2/b.txt|3|Nachpruefung-Hostname|wertC"].map(zerlegeFundZeile);
    const kopie = (l) => l.map(f => Object.assign({}, f));
    assert(vergleicheFundMultimengen(basis, kopie(basis).reverse()).length === 0, "Vergleich: gleiche Funde in anderer Reihenfolge bestehen");
    const fehlt = vergleicheFundMultimengen(basis, kopie(basis).filter(f => f.quelle !== "K2/b.txt"));
    assert(fehlt.length === 1 && fehlt[0].startsWith("fehlend: K2/b.txt Nachpruefung-Hostname Zeile 3"), `Vergleich: fehlender Fund fällt durch (${fehlt.join("; ")})`);
    const extra = vergleicheFundMultimengen(basis, kopie(basis).concat([zerlegeFundZeile("K3/c.txt|4|Nachpruefung-SID|wertD")]));
    assert(extra.length === 1 && extra[0].startsWith("zusätzlich: K3/c.txt Nachpruefung-SID Zeile 4"), `Vergleich: zusätzlicher Fund fällt durch (${extra.join("; ")})`);
    const haeufig = vergleicheFundMultimengen(basis, kopie(basis).slice(1));
    assert(haeufig.length === 1 && haeufig[0].startsWith("abweichende Häufigkeit: K1/a.txt Nachpruefung-Benutzer Zeile 1, Soll 2, Ist 1"), `Vergleich: abweichende Häufigkeit fällt durch (${haeufig.join("; ")})`);
    const geaendert = kopie(basis); geaendert[2].fund = "wertX";
    const inhalt = vergleicheFundMultimengen(basis, geaendert);
    assert(inhalt.length === 1 && inhalt[0].startsWith("gleicher Fundort, abweichender Inhalt: K1/a.txt Nachpruefung-Geheimnis Zeile 2"), `Vergleich: geänderter Fundwert am gleichen Fundort fällt durch (${inhalt.join("; ")})`);
    const gross = kopie(basis); gross[3].fund = "WERTC";
    assert(vergleicheFundMultimengen(basis, gross).length === 1, "Vergleich: Groß-/Kleinschreibung des Fundwerts zählt (ordinal)");
    const alle = [].concat(fehlt, extra, haeufig, inhalt).join(" ");
    assert(!/wert[A-DX]/i.test(alle), "Vergleich: Diagnosen enthalten keine Fundwerte");
  }

  // --- 22. Leck-Katalog (tests/leck-katalog.json) und unabhängige Nachprüfung ---
  console.log("--- 22. Leck-Katalog und unabhängige Nachprüfung ---");
  {
    const katalog = JSON.parse(fs.readFileSync(path.join(__dirname, "leck-katalog.json"), "utf8"));
    assert(katalog.faelle.length >= 15, `Leck-Katalog: mindestens 15 Fälle (${katalog.faelle.length})`);
    const hatNachpruefung = typeof core.nachpruefen === "function";
    assert(hatNachpruefung, "Nachprüfung: core.nachpruefen vorhanden");
    const kCfg = core.buildEngineConfig(diskRules, { netzerhaltend: true });
    // Ein Fund deckt den Zielwert, wenn er ihm entspricht oder ihn als eigenen Teil enthält
    // ('Alpha BetaSecret77', 'part1"SecretTail77', '-42.5e3'); eine andere Fundstelle genügt nicht
    const deckt = (fund, wert) => fund === wert || String(fund).split(/[\s"'`]+/).some(t => t === wert || t.replace(/^[-+]/, "") === wert);
    for (const k of katalog.faelle) {
      const dateien = k.dateien || [{ path: k.id + ".txt", text: k.eingabe }];
      const kState = new core.AnonState();
      const lauf = core.reprocessFilesWithState(dateien, diskRules, {}, kState, { overrides: { netzerhaltend: true } });
      const ausgabe = lauf.results.map(r => r.anonText).join("\n");
      const tabelle = JSON.stringify(kState.toJSON());
      const rohFunde = hatNachpruefung ? [].concat(...dateien.map(d => core.nachpruefen(d.text, d.path, kCfg))) : [];
      for (const z of k.ziele) {
        const kurz = `${k.id}/${z.kategorie}`;
        assert(!ausgabe.includes(z.wert), `${kurz}: Zielwert steht nicht in der Ausgabe`);
        if (z.art === "geheimnis") assert(!tabelle.includes(z.wert), `${kurz}: Geheimnis steht nicht in der Zuordnungstabelle`);
        const soll = katalog.kategorien[z.kategorie];
        assert(rohFunde.some(f => f.kategorie === soll && deckt(f.fund, z.wert)),
          `${kurz}: Nachprüfung erkennt den Zielwert auf der Roheingabe als ${soll}`);
      }
    }
    // Parität A == B: Nachprüfung auf den Roheingaben (Katalog, tests/beispiele) gegen tests/nachpruefung-erwartet.json
    if (hatNachpruefung) {
      const quellen = [];
      for (const k of katalog.faelle) for (const d of (k.dateien || [{ path: k.id + ".txt", text: k.eingabe }])) quellen.push([k.id + "/" + d.path, d.text]);
      for (const f of fs.readdirSync(BEISPIELE_DIR).filter(n => !n.startsWith(".")).sort()) quellen.push(["beispiele/" + f, fs.readFileSync(path.join(BEISPIELE_DIR, f), "utf8")]);
      const zeilenNach = [];
      for (const [q, t] of quellen) for (const f of core.nachpruefen(t, q, kCfg)) zeilenNach.push(`${q}|${f.zeile}|${f.kategorie}|${f.fund}`);
      const sollPfad = path.join(__dirname, "nachpruefung-erwartet.json");
      if (AKTUALISIEREN) fs.writeFileSync(sollPfad, JSON.stringify(zeilenNach, null, 2) + "\n", "utf8");
      const sollNach = fs.existsSync(sollPfad) ? JSON.parse(fs.readFileSync(sollPfad, "utf8")) : [];
      const diagNach = vergleicheFundMultimengen(sollNach.map(zerlegeFundZeile), zeilenNach.map(zerlegeFundZeile));
      for (const d of diagNach) console.error("    [Parität Nachprüfung] " + d);
      assert(diagNach.length === 0, `Parität: Nachprüfung auf den Roheingaben entspricht tests/nachpruefung-erwartet.json (Soll ${sollNach.length}, Ist ${zeilenNach.length}, Abweichungen ${diagNach.length})`);
    }
    // Fix Spaltenerkennung: Tabelle endet an Befehlszeile, Trennlinie nach Daten oder Zeile außerhalb des Spaltenrasters
    {
      const sep = "-".repeat(110);
      const tabelleText = ["show interface brief", sep,
        "Port      Native  Mode   Type           Enabled Status  Reason                  Speed   Description",
        "          VLAN                                                                  (Mb/s)", sep,
        "1/1/1     1       access 1GbT           yes     up                              1000    Uplink-Weber",
        "1/1/2     1       access 1GbT           yes     down    Waiting for link        --      --",
        "show logging",
        "2024-01-15T10:00:00.000+00:00 hpe-sshd[1234]: login failed for user bwagner from 198.51.100.4 port 22",
        "Build Date              : 2024-01-15 10:00:00 UTC                                      UTC",
        "show vlan", sep,
        "VLAN  Name                              Status  Reason          Type      Interfaces                           Description", sep,
        "1     DEFAULT_VLAN_1                    up      ok              default   1/1/1-1/1/2                          Standard", ""].join("\n");
      const tNach = core.nachpruefen(tabelleText, "t.txt", kCfg).filter(f => f.kategorie === "Nachpruefung-Beschreibung").map(f => f.fund);
      assert(JSON.stringify(tNach) === '["Uplink-Weber","Standard"]', `Fix 1: Nachprüfung meldet die Descriptions der Brief- und VLAN-Tabelle, nicht Log oder UTC (${JSON.stringify(tNach)})`);
      const tAus = core.processText(tabelleText, kCfg, new core.AnonState());
      const tZeilen = tAus.split("\n");
      assert(/1000    TEXT-1$/.test(tZeilen[5]) && tAus.indexOf("Uplink-Weber") < 0, "Fix 1: Description der Brief-Tabelle ersetzt");
      assert(/login failed for user USER-1 from NET-1\.H1 port 22$/.test(tZeilen[8]), `Fix 1: Benutzer und IP nach Benutzer-/IP-Regel, nicht als Spaltenwert (${tZeilen[8]})`);
      assert(tZeilen[9] === "Build Date              : 2024-01-15 10:00:00 UTC                                      UTC", "Fix 1: 'UTC' bleibt stehen");
      assert(/Interfaces {27}Description$/.test(tZeilen[12]) && /1\/1\/1-1\/1\/2 {26}TEXT-[0-9]+$/.test(tZeilen[14]) && tZeilen[14].indexOf("DEFAULT_VLAN_1") > 0, `Fix 1: VLAN-Kopfzeile bleibt, Standardname bleibt, VLAN-Description ersetzt (${tZeilen[14].slice(-40)})`);
      const tTab = core.processText("Port\tNative\tDescription\n1/1/1\t1\tUplink-Weber\nshow logging ohne Tabulator\n1/1/2\t1\tLog-Zeile\n", kCfg, new core.AnonState());
      assert(tTab.indexOf("Uplink-Weber") < 0 && tTab.indexOf("Log-Zeile") >= 0, `Fix 1: tabulatorgetrennte Tabelle endet an einer Zeile ohne Tabulator (${JSON.stringify(tTab)})`);
      const tTrenn = core.processText(["Port      Native  Type   Description", sep, "1/1/1     1       1GbT   Uplink-Weber", sep, "1/1/9     1       1GbT   Nach-Trennlinie", ""].join("\n"), kCfg, new core.AnonState());
      assert(tTrenn.indexOf("Uplink-Weber") < 0 && tTrenn.indexOf("Nach-Trennlinie") < 0, "Fail-safe: Trennlinie nach Datenzeilen beendet die Tabelle nicht");
      // Zeile außerhalb des Rasters ohne Ankerfeld: trotzdem ersetzt und zusätzlich als Fund gemeldet
      const unsicherText = [sep, "Port      Native  Mode   Type           Enabled Status  Reason                  Speed   Description", sep,
        "1/1/1     1       access 1GbT           yes     up                              1000    Uplink-Weber",
        "1/1/7     1       access 1GbT           yes     down    Link flap detected (err-disabled) Kiosk Wagner",
        "1/1/8     1       access 1GbT           yes     up                              1000    Telefon Wolf", ""].join("\n");
      const uAus = core.processText(unsicherText, kCfg, new core.AnonState());
      assert(uAus.indexOf("Wagner") < 0 && uAus.indexOf("Wolf") < 0 && uAus.indexOf("Uplink-Weber") < 0, `Fail-safe: Zeile außerhalb des Rasters wird ersetzt, Tabelle läuft weiter (${uAus.split("\n")[4]})`);
      const uLauf = core.reprocessFilesWithState([{ path: "u.txt", text: unsicherText }], diskRules, {}, new core.AnonState(), { overrides: { netzerhaltend: true } });
      const uFunde = uLauf.findings.filter(f => f.kategorie === "Rest-Tabellenzeile");
      assert(uFunde.length === 1 && uFunde[0].zeile === 5, `Fail-safe: nicht eindeutige Zeile wird als Fund gemeldet (${JSON.stringify(uFunde.map(f => f.zeile))})`);
      assert(core.freigabeKategorie("Rest-Tabellenzeile", "x") === "Tabellenfeld", "Fail-safe: nicht eindeutige Zeile ist nach Prüfung freigebbar");
      // Nachprüfung meldet Freitext in der letzten Spalte auch nach Zeilen außerhalb des Rasters, Statuswerte nicht
      const nUnsicher = core.nachpruefen(unsicherText, "u.txt", kCfg).filter(f => f.kategorie === "Nachpruefung-Beschreibung").map(f => f.fund);
      assert(JSON.stringify(nUnsicher) === '["Uplink-Weber","Kiosk Wagner","Telefon Wolf"]', `Nachprüfung: Freitext in der letzten Spalte jeder Zeile (${JSON.stringify(nUnsicher)})`);
      // Standardnamen von VLANs bleiben stehen und sind kein Restfund
      const vText = "VLAN Name                             Status    Ports\n---- -------------------------------- --------- ------\n1    default                          active    Gi0/1\n10   VLAN0010                         active    Gi0/3\n1002 fddi-default                     act/unsup\n";
      assert(core.processText(vText, kCfg, new core.AnonState()) === vText && core.nachpruefen(vText, "v.txt", kCfg).length === 0, "show vlan: Standardnamen (default, VLAN0010, fddi-default) bleiben, kein Fund");
      const tPrompt = core.nachpruefen(["Port      Native  Type   Description", "1/1/1     1       1GbT   Uplink-Weber", "<brw-core07>display current-configuration", "sw-x1# show clock     10:00:00 Description-Spalte", ""].join("\n"), "p.txt", kCfg).filter(f => f.kategorie === "Nachpruefung-Beschreibung").map(f => f.fund);
      assert(JSON.stringify(tPrompt) === '["Uplink-Weber"]', `Fix 1: Prompt-Zeilen (<name>, name#) beenden die Tabelle (${JSON.stringify(tPrompt)})`);
    }
    // Fix Namensspalten: nur die Namensspalte ersetzen, übrige Spalten bleiben unverändert
    {
      const kat = Object.fromEntries(katalog.faelle.map(f => [f.id, f.eingabe]));
      const aus = (id) => core.processText(kat[id], kCfg, new core.AnonState()).split("\n");
      const ein = (id) => kat[id].split("\n");
      const c = aus("K26"), ce = ein("K26");
      assert(c[1].endsWith("connected    10         a-full  a-1000 10/100/1000BaseTX") && c[1].indexOf("Becker") < 0 && c[1].length === ce[1].length, `Namensspalten: Cisco Name ersetzt, Status bis Type unverändert (${c[1]})`);
      assert(c[2].endsWith(" notconnect 20        auto    auto 10/100/1000BaseTX") && c[2].indexOf("Hoffmann") < 0, `Namensspalten: überlanger Name ersetzt, Rest bleibt (${c[2]})`);
      assert(c[3] === ce[3], "Namensspalten: leerer Name bleibt leer");
      const n = aus("K27");
      assert(/^  1     TEXT-[0-9]+$/.test(n[4]) && /^  2     TEXT-[0-9]+$/.test(n[5]) && n[6] === "  3", `Namensspalten: ArubaOS-Switch show name ersetzt (${n.slice(4, 7).join(" | ")})`);
      const pr = aus("K28");
      assert(/^admin@HOST-[0-9]+> show version$/.test(pr[0]) && /^admin@HOST-[0-9]+# show clock$/.test(pr[1]), `Namensspalten: Prompt user@host (${pr.join(" | ")})`);
      const d = aus("K29"), de = ein("K29");
      assert(d[1].endsWith("Gig 1/0/1         150             R S I  C9300-48P Gig 1/0/48") && /^HOST-[0-9]+ /.test(d[1]) && d[3] === de[3], `Namensspalten: CDP nur Device ID ersetzt, Local Intrfce bleibt (${d[1]} | ${d[3]})`);
      assert(d[2].indexOf("brw-core12") < 0, "Namensspalten: umbrochene Device ID ersetzt");
      const nAlle = core.nachpruefen("ID  Desc             Status\n1   Lager-Engel      up\n2   --               down\n\nIdx Alias        Port-Name      Speed\n1   Halle-Ost    Tor-Seidel     1000\n", "n.txt", kCfg).filter(f => f.kategorie === "Nachpruefung-Beschreibung").map(f => f.fund);
      assert(JSON.stringify(nAlle) === '["Lager-Engel","Halle-Ost","Tor-Seidel"]', `Nachprüfung: Spalten Name/Desc/Alias/Port-Name in beliebiger Position (${JSON.stringify(nAlle)})`);
    }
    // Fix Praxistest 2: Befehls- und Logzeilen ohne Wert sind kein sicheres Geheimnis; Zeitstempel, Versionen und Kopfzeilen sind keine Benutzer
    {
      const pt = JSON.parse(fs.readFileSync(path.join(__dirname, "praxistest2.json"), "utf8"));
      assert(pt.befehle.length === 30 && pt.logzeilen.length === 15, "Praxistest 2: 30 Befehlszeilen, 15 Logzeilen");
      const lauf = (text) => core.reprocessFilesWithState([{ path: "p.txt", text }], diskRules, {}, new core.AnonState(), { overrides: { netzerhaltend: true } });
      const bLauf = lauf(pt.befehle.join("\n") + "\n");
      const bSicher = core.bildeFundgruppen(bLauf.findings, null).filter(g => g.sicheresGeheimnis);
      assert(bSicher.length === 0, `Praxistest 2: 30 Befehlszeilen ohne Wert ergeben keinen sicheren Fund (${bSicher.map(g => g.fund).join(" | ")})`);
      const aaa = bLauf.findings.filter(f => /^(?:no )?aaa /.test(f.kontext));
      assert(aaa.length === 0, `Praxistest 2: AAA-Befehlszeilen sind kein Fund (${aaa.map(f => f.kategorie).join(",")})`);
      const lLauf = lauf(pt.logzeilen.join("\n") + "\n");
      assert(lLauf.findings.length === 0, `Praxistest 2: 15 Logzeilen ohne Wert ergeben keinen Fund (${lLauf.findings.map(f => f.kategorie + ":" + f.zeile).join(",")})`);
      assert(core.freigabeKategorie("Verdacht-Zugangsdaten", "password Abc12345") === null && core.freigabeKategorie("Verdacht-Zugangsdaten", "password allow-fail-through") === "Verdacht", "Praxistest 2: sicher nur mit Schlüsselwort und typischem Wert");
      const cp = "Checkpoint name  Type     Writer  Date(YYYY/MM/DD)       Image Version\n---------------  -------  ------  ---------------------  -------------\nstartup-config   startup  User    2026-07-02T18:42:25Z   GL.10.13.1020\nckpt-20260702    latest   User    2026/07/02 18:42:25    GL.10.13.1020\n";
      const cpLauf = lauf(cp);
      assert(cpLauf.results[0].anonText === cp && cpLauf.findings.length === 0, `Praxistest 2: Zeitstempel und Firmware-Versionen sind kein Benutzername (${cpLauf.findings.map(f => f.kategorie + ":" + f.fund).join(" | ")})`);
      const kopf = "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n 1234 root      20   0  123456  12345   1234 S   0.0   0.1   0:00.12 hpe-restd\nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 167000 11000 ?        Ss   10:00   0:01 /sbin/init\n    Line       User       Host(s)              Idle       Location\n";
      const kLauf = lauf(kopf);
      assert(kLauf.findings.length === 0 && kLauf.results[0].anonText === kopf, `Praxistest 2: Kopfzeilen (top, ps, show users) liefern keinen Benutzernamen (${kLauf.findings.map(f => f.kategorie + ":" + f.fund).join(" | ")})`);
      // SSH Public Keys: Platzhalter SSHKEY-n, rückübersetzbar über die Tabelle
      const ssh = katalog.faelle.find(f => f.id === "K30").eingabe;
      const sState = new core.AnonState();
      const sAus = core.processText(ssh, kCfg, sState);
      assert(/^user admin authorized-key SSHKEY-1$/m.test(sAus) && /^SSHKEY-2$/m.test(sAus), `Praxistest 2: SSH Public Keys werden SSHKEY-n (${JSON.stringify(sAus)})`);
      assert(core.deanonymizeText(sAus, sState) === ssh, "Praxistest 2: SSH Public Keys über die Tabelle rückübersetzbar");
      assert(core.nachpruefen(sAus, "s.txt", kCfg).length === 0, "Praxistest 2: SSHKEY-n ist kein Restfund");
    }
    // Fix 2: eigene Platzhalter (auch mit Satzzeichen) sind kein Restfund der Nachprüfung
    {
      const pText = "description Uplink zu (HOST-1), siehe TEXT-2;\n Port Description : [USER-1]\nhostname HOST-1.\nuser USER-3,\nPort      Native  Type   Description\n1/1/1     1       1GbT   TEXT-1 (FIRMA-1)\n";
      const pFunde = core.nachpruefen("description (HOST-1), TEXT-2;\n Port Description : [USER-1]\nhostname HOST-1.\nuser USER-3,\nPort      Native  Type   Description\n1/1/1     1       1GbT   TEXT-1 (FIRMA-1)\n", "p.txt", kCfg);
      assert(pFunde.length === 0, `Fix 2: Nachprüfung meldet keine eigenen Platzhalter (${JSON.stringify(pFunde.map(f => f.kategorie + ":" + f.fund))})`);
      assert(core.nachpruefen(pText, "p.txt", kCfg).length === 1, "Fix 2: echter Freitext neben Platzhaltern wird weiter gemeldet");
    }

    // Rückwirkend und dateiübergreifend: mehrdeutige Benutzer nur im Feldkontext
    const mState = new core.AnonState();
    const mLauf = core.reprocessFilesWithState([
      { path: "a.log", text: "show backup status\nbackup completed\n" },
      { path: "b.log", text: "user backup group operators\n" }
    ], diskRules, {}, mState, { overrides: { netzerhaltend: true } });
    assert(mLauf.results[0].anonText === "show backup status\nbackup completed\n" && mLauf.results[1].anonText === "user USER-1 group operators\n",
      `A2-Folge 2: gelernter Benutzer 'backup' nur im Feldkontext ersetzt (${JSON.stringify(mLauf.results.map(r => r.anonText))})`);
    // Die Nachprüfung meldet auf den anonymisierten Beispielen keine Fehlalarme
    if (hatNachpruefung) {
      for (const f of fs.readdirSync(ERWARTET_DIR).filter(n => !n.startsWith("."))) {
        const nf = core.nachpruefen(fs.readFileSync(path.join(ERWARTET_DIR, f), "utf8"), f, kCfg);
        assert(nf.length === 0, `Nachprüfung: keine Fehlalarme in tests/erwartet/${f} (${JSON.stringify(nf.map(x => x.kategorie + ":" + x.zeile))})`);
      }
    }
  }

  // --- 23. Bedienoberfläche: kategoriegebundene Freigaben (ausnahmen.freigegeben) ---
  console.log("--- 23. Kategoriegebundene Freigaben (ausnahmen.freigegeben) ---");
  {
    const frText = '<Data Name="TargetUserName">jdoe7</Data>\nhostname jdoe7\n';
    const mitFreigabe = (liste) => {
      const r = JSON.parse(JSON.stringify(diskRules));
      r.ausnahmen.freigegeben = liste;
      return core.buildEngineConfig(r, {});
    };
    const hatDetail = typeof core.auditTextDetail === "function";
    assert(hatDetail, "Freigaben: core.auditTextDetail vorhanden");
    if (hatDetail) {
      const ohne = core.auditTextDetail(frText, "f.txt", core.buildEngineConfig(diskRules, {}));
      assert(ohne.funde.some(f => f.kategorie === "Nachpruefung-Benutzer") && ohne.freigegeben === 0, `Freigaben: ohne Freigabe wird der Benutzer gemeldet (${ohne.funde.length})`);
      const mit = core.auditTextDetail(frText, "f.txt", mitFreigabe([{ kategorie: "Benutzer", wert: "jdoe7" }]));
      assert(!mit.funde.some(f => /Benutzer/.test(f.kategorie)), "Freigaben: freigegebener Benutzer wird in Kategorie Benutzer nicht gemeldet");
      assert(mit.funde.some(f => /Hostname/.test(f.kategorie)), "Freigaben: derselbe Wert als Hostname wird weiter gemeldet");
      assert(mit.freigegeben === ohne.funde.filter(f => /Benutzer/.test(f.kategorie)).length && mit.freigegeben > 0, `Freigaben: bewusst freigegebene Funde werden gezählt (${mit.freigegeben})`);
      assert(core.auditText(frText, "f.txt", mitFreigabe([{ kategorie: "Benutzer", wert: "jdoe7" }])).length === mit.funde.length, "Freigaben: auditText liefert dieselben Funde wie auditTextDetail");
      const gross = core.auditTextDetail(frText, "f.txt", mitFreigabe([{ kategorie: "Benutzer", wert: "JDOE7" }]));
      assert(gross.freigegeben === 0, "Freigaben: Wert wird exakt verglichen (Groß-/Kleinschreibung zählt)");
      const geheim = core.auditTextDetail("password Geheim77x\n", "f.txt", mitFreigabe([{ kategorie: "Geheimnis", wert: "Geheim77x" }]));
      assert(geheim.freigegeben === 0 && geheim.funde.length > 0, "Freigaben: Geheimnisse sind nicht freigebbar");
    }
    // Verdachtsfunde (Heuristik ohne eindeutiges Schlüsselwort) sind als "Verdacht" freigebbar, sicher erkannte Geheimnisse nicht
    if (hatDetail) {
      const blob = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
      const blobText = "ArubaOS-CX build id " + blob + "\n";
      const vOhne = core.auditTextDetail(blobText, "b.txt", core.buildEngineConfig(diskRules, {}));
      assert(vOhne.funde.some(f => f.kategorie === "Verdacht-Geheimnis-Blob"), `Verdacht: Build-ID wird als Verdacht-Geheimnis-Blob gemeldet (${vOhne.funde.map(f => f.kategorie).join(",")})`);
      const vMit = core.auditTextDetail(blobText, "b.txt", mitFreigabe([{ kategorie: "Verdacht", wert: blob }]));
      assert(vMit.funde.length === 0 && vMit.freigegeben === 1, `Verdacht: freigegebene Build-ID ist kein Restfund und wird gezählt (${vMit.funde.length}/${vMit.freigegeben})`);
      const sicher = [["Rest-Geheimnis", "password Abc12345"], ["Verdacht-Zugangsdaten", "password Abc12345"], ["Verdacht-Zugangsdaten", "secret Abc12345"], ["Verdacht-Hash", "$6$abcdefghij$klmnopqrstuv"], ["Verdacht-Teilmaskierung", "*****x"]];
      for (const [k, w] of sicher) assert(core.freigabeKategorie(k, w) === null, `Sicher erkanntes Geheimnis ${k} ist nicht freigebbar`);
      const verdacht = [["Verdacht-Geheimnis-Blob", blob], ["Verdacht-Zugangsdaten", "token Abc12345"], ["Verdacht-Zugangsdaten", "pwd Abc12345"], ["Nachpruefung-Geheimnis", "Abc12345"], ["Nachpruefung-Teilmaskierung", "ab*****"]];
      for (const [k, w] of verdacht) assert(core.freigabeKategorie(k, w) === "Verdacht", `Verdachtsfund ${k} (${w.split(" ")[0]}) ist als Verdacht freigebbar`);
      assert(core.freigabeKategorie("Nachpruefung-SID", "S-1-5-21-1-2-3-500") === "SID", "Nachprüfung SID ist freigebbar (Kategorie SID)");
      assert(core.freigabeKategorie("Nachpruefung-Beschreibung", "Uplink-Weber") === "Freitext", "Nachprüfung Beschreibung ist als Freitext freigebbar");
      assert(core.pruefeFreigabeEintrag({ kategorie: "Verdacht", wert: blob }) === null && core.pruefeFreigabeEintrag({ kategorie: "Geheimnis", wert: blob }) !== null, "Freigabe-Kategorie Verdacht gültig, Geheimnis weiter ungültig");
    }
    const ungueltig = core.validateAndMergeEigeneBegriffe(diskRules, { muster: { "ausnahmen.freigegeben": [{ kategorie: "Geheimnis", wert: "x1" }, { kategorie: "Benutzer", wert: "" }] } });
    assert(!ungueltig.valid && ungueltig.errors.length === 2, `Freigaben: ungültige Einträge werden abgelehnt (${ungueltig.errors.length})`);
    assert(ungueltig.errors.every(e => !e.includes("x1")), "Freigaben: Fehlermeldungen enthalten keine Werte");
    const lokal = core.validateAndMergeEigeneBegriffe(diskRules, { muster: { "ausnahmen.freigegeben": [{ kategorie: "Benutzer", wert: "jdoe7" }] } });
    assert(lokal.valid && (lokal.mergedRules.ausnahmen.freigegeben || []).length === 1, "Freigaben: Einträge aus anon-regeln.lokal.json werden übernommen");
    const exportiert = JSON.parse(core.exportLokaleBegriffeJson({ muster: { "ausnahmen.freigegeben": [{ kategorie: "Benutzer", wert: "jdoe7" }] } }, diskRules));
    assert(exportiert.ausnahmen && Array.isArray(exportiert.ausnahmen.freigegeben) && exportiert.ausnahmen.freigegeben[0].wert === "jdoe7", "Freigaben: Export nach anon-regeln.lokal.json enthält ausnahmen.freigegeben");
    const wieder = core.importLokaleBegriffeJson(JSON.stringify(exportiert));
    assert(wieder.muster["ausnahmen.freigegeben"] && wieder.muster["ausnahmen.freigegeben"].length === 1, "Freigaben: Import aus anon-regeln.lokal.json liest ausnahmen.freigegeben");

    // Parität: anon.ps1 wertet ausnahmen.freigegeben aus und zählt sie im Bericht (ohne Werte)
    if (pwshCheck.status === 0) {
      const frDir = fs.mkdtempSync(path.join(os.tmpdir(), "anon-freigabe-"));
      fs.writeFileSync(path.join(frDir, "ein.txt"), frText.split("\n")[0] + "\n", "utf8");
      const esc = (p) => p.replace(/\\/g, "\\\\");
      const lauf = (liste, name) => {
        const lok = path.join(frDir, name + ".lokal.json");
        fs.writeFileSync(lok, JSON.stringify({ ausnahmen: { freigegeben: liste } }), "utf8");
        const aus = path.join(frDir, "aus-" + name);
        const cmd = `& "${esc(PS1_PATH)}" -Eingabe "${esc(path.join(frDir, "ein.txt"))}" -Ausgabe "${esc(aus)}" -Regeln "${esc(RULES_PATH)}" -LokaleRegeln "${esc(lok)}" -TabellenPfad "${esc(path.join(frDir, "tab-" + name + ".json"))}" -Unverschluesselt; exit $LASTEXITCODE`;
        const r = spawnSync("pwsh", ["-NoProfile", "-Command", cmd], { encoding: "utf8" });
        const berPfad = path.join(aus, "bericht.json");
        return { code: r.status, bericht: fs.existsSync(berPfad) ? JSON.parse(fs.readFileSync(berPfad, "utf8")) : null, konsole: r.stdout || "" };
      };
      const lb = lauf([{ kategorie: "Benutzer", wert: "jdoe7" }], "benutzer");
      assert(lb.code === 0 && lb.bericht && lb.bericht.bewusstFreigegeben >= 1, `Parität: anon.ps1 mit Freigabe (Benutzer) ohne Restfunde, Bericht zählt bewusstFreigegeben (${lb.code}, ${lb.bericht && lb.bericht.bewusstFreigegeben})`);
      assert(!JSON.stringify(lb.bericht || {}).includes("jdoe7") && !lb.konsole.includes("jdoe7"), "Parität: Bericht und Konsole enthalten den freigegebenen Wert nicht");
      const lh = lauf([{ kategorie: "Hostname", wert: "jdoe7" }], "hostname");
      assert(lh.code === 2, `Parität: Freigabe als Hostname gibt den Benutzer nicht frei (${lh.code})`);
      const js = core.reprocessFilesWithState([{ path: "ein.txt", text: frText.split("\n")[0] + "\n" }], diskRules, { muster: { "ausnahmen.freigegeben": [{ kategorie: "Benutzer", wert: "jdoe7" }] } }, new core.AnonState(), {});
      assert(js.ok && js.findings.length === 0 && js.freigegeben === (lb.bericht && lb.bericht.bewusstFreigegeben), `Parität: anonymisierer.html zählt gleich viele freigegebene Funde (${js.freigegeben})`);
      fs.rmSync(frDir, { recursive: true, force: true });
    }
  }

  // --- 24. Bedienlogik (rein, ohne DOM) ---
  console.log("--- 24. Bedienlogik: Ablaufstatus, Fundgruppen, Entscheidungen, Vorschau, Dateiliste ---");
  {
    const st = core.berechneAblaufStatus;
    assert(st({ dateien: 0 }).code === "KEINE_DATEIEN" && st({ dateien: 0 }).ton !== "ok", "Ablauf: ohne Dateien neutral, nicht grün");
    assert(st({ dateien: 3 }).text === "Noch nicht geprüft" && st({ dateien: 3 }).ton === "neutral" && st({ dateien: 3 }).gesperrt, "Ablauf: 'Noch nicht geprüft' neutral und gesperrt");
    assert(st({ dateien: 3, laeuft: true, fortschritt: { aktuell: 2, gesamt: 3 } }).text === "Verarbeitung läuft (Datei 2 von 3)", "Ablauf: 'Verarbeitung läuft (Datei x von y)'");
    const offen = st({ dateien: 3, lauf: { offeneGruppen: 4, gruppen: 4 }, freigabe: false });
    assert(offen.text === "4 Fundgruppen brauchen eine Entscheidung" && offen.gesperrt && offen.grund && offen.aktion, "Ablauf: offene Fundgruppen mit Grund und nächster Aktion");
    assert(st({ dateien: 3, lauf: { offeneGruppen: 1, gruppen: 1 } }).text === "1 Fundgruppe braucht eine Entscheidung", "Ablauf: Einzahl bei einer Fundgruppe");
    const sauber = st({ dateien: 3, lauf: { offeneGruppen: 0, gruppen: 0, freigegeben: 2 }, freigabe: true });
    assert(sauber.code === "KEINE_RESTFUNDE" && !sauber.gesperrt && sauber.text.startsWith("Keine Restfunde nach aktivem Regelwerk – Vorschau prüfen") && sauber.text.includes("2 bewusst freigegeben"), `Ablauf: ohne Restfunde frei, freigegebene gezählt (${sauber.text})`);
    assert(st({ dateien: 3, lauf: { offeneGruppen: 0, gruppen: 0 }, freigabe: true, veraltet: true }).code === "VERALTET", "Ablauf: Änderung nach dem Lauf -> 'Ergebnis veraltet'");
    const unv = st({ dateien: 3, lauf: { offeneGruppen: 0, gruppen: 0, nichtVerarbeitet: 2 }, freigabe: true });
    assert(unv.text.startsWith("Unvollständig – 2 Dateien nicht verarbeitet") && /fehlen im Ergebnis/.test(unv.grund) && unv.gesperrt && /entfernen/.test(unv.aktion), "Ablauf: 'Unvollständig – N Dateien nicht verarbeitet' sperrt den Download");
    assert(st({ dateien: 3, lauf: { offeneGruppen: 0, gruppen: 0, isProbe: true }, freigabe: false }).gesperrt, "Ablauf: Trockenlauf gibt nicht frei");

    // Fundgruppen: Rest- und Nachprüfungsfund desselben Benutzers ergeben eine Karte mit Fundorten
    const fg = core.bildeFundgruppen([
      { datei: "a.txt", zeile: 3, kategorie: "Rest-Benutzer", fund: "jdoe7", kontext: "user jdoe7 x" },
      { datei: "a.txt", zeile: 3, kategorie: "Nachpruefung-Benutzer", fund: "jdoe7", kontext: "user jdoe7 x" },
      { datei: "b.txt", zeile: 9, kategorie: "Nachpruefung-Benutzer", fund: "jdoe7", kontext: "for user jdoe7" },
      { datei: "b.txt", zeile: 2, kategorie: "Rest-Geheimnis", fund: "Geheim9z", kontext: "password Geheim9z" },
      { datei: "b.txt", zeile: 4, kategorie: "Sperrbegriff", fund: "Werk-Nord", kontext: "Werk-Nord-alt" },
      { datei: "c.txt", zeile: 1, kategorie: "Verdacht-Geheimnis-Blob", fund: "9f8e7d6c5b4a39281706f5e4d3c2b1a0", kontext: "ArubaOS-CX build id 9f8e7d6c5b4a39281706f5e4d3c2b1a0" },
      { datei: "c.txt", zeile: 2, kategorie: "Nachpruefung-Geheimnis", fund: "9f8e7d6c5b4a39281706f5e4d3c2b1a0", kontext: "key 9f8e7d6c5b4a39281706f5e4d3c2b1a0" }
    ], null);
    const gB = fg.find(g => g.art === "Benutzer");
    assert(fg.length === 4 && gB && gB.anzahl === 3 && gB.orte.length === 2 && gB.dateien.length === 2 && gB.text === "Möglicher Benutzername", `Fundgruppen: eine Karte je Bedeutung und Wert, mit Fundorten (${fg.length})`);
    assert(gB.kannErsetzen && gB.kannUnveraendert, "Fundgruppen: Benutzer kann ersetzt oder unverändert gelassen werden");
    const gG = fg.find(g => g.art === "Geheimnis");
    assert(gG.kannErsetzen && !gG.kannUnveraendert && gG.sicheresGeheimnis, "Fundgruppen: sicher erkanntes Geheimnis kann nicht unverändert bleiben");
    assert(JSON.stringify(gG.aktionen) === '["ersetzen","datei-entfernen"]' && core.aktionText(gG, "ersetzen") === "Alle Vorkommen ersetzen (*****)", `Fundgruppen: sicheres Geheimnis nur maskieren oder Datei entfernen (${gG.aktionen})`);
    const gV = fg.find(g => g.art === "Verdacht");
    assert(gV && gV.anzahl === 2 && gV.verdacht && !gV.sicheresGeheimnis && gV.kannUnveraendert, "Fundgruppen: Build-ID (Hex-Blob und Nachprüfung) ist ein Verdachtsfund");
    assert(JSON.stringify(gV.aktionen) === '["unveraendert","maskieren"]' && gV.bestaetigung === "Ich habe geprüft: kein Geheimnis" && core.aktionText(gV, "maskieren") === "Als Geheimnis maskieren (*****)", `Fundgruppen: Verdacht freigeben (mit Bestätigung) oder maskieren (${gV.aktionen})`);
    const eV = core.entscheidungsEintraege(gV, "unveraendert");
    assert(eV.freigegeben.length === 1 && eV.freigegeben[0].kategorie === "Verdacht", "Entscheidung 'Unverändert lassen' bei Verdacht: Freigabe in Kategorie Verdacht");
    const eM = core.entscheidungsEintraege(gV, "maskieren");
    assert(eM.geheimnisMuster.length === 1 && eM.geheimnisMuster[0].ersetzen === "*****" && eM.festeZuordnung.length === 0, "Entscheidung 'Als Geheimnis maskieren': Muster mit *****, keine Zuordnung");
    // Fix 3: ein Wert ergibt höchstens eine Fundgruppe; die strengste Aktion gilt
    const BID = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
    const fg3 = core.bildeFundgruppen([
      { datei: "c.txt", zeile: 1, kategorie: "Verdacht-Geheimnis-Blob", fund: BID, kontext: "build id " + BID },
      { datei: "c.txt", zeile: 1, kategorie: "Nachpruefung-Seriennummer", fund: BID, kontext: "Serial Number: " + BID },
      { datei: "d.txt", zeile: 3, kategorie: "Rest-Tabellenfeld", fund: BID, kontext: "1/1/1 " + BID }
    ], null);
    assert(fg3.length === 1 && fg3[0].anzahl === 3 && fg3[0].verdacht && fg3[0].bestaetigung && JSON.stringify(fg3[0].aktionen) === '["unveraendert","maskieren"]', `Fix 3: Build-ID in drei Kategorien ergibt eine Fundgruppe (Verdacht) (${fg3.length}, ${fg3.map(g => g.art).join(",")})`);
    const e3 = core.entscheidungsEintraege(fg3[0], "unveraendert");
    assert(JSON.stringify(e3.freigegeben.map(f => f.kategorie).sort()) === '["Seriennummer","Tabellenfeld","Verdacht"]', `Fix 3: Freigabe gilt für alle Kategorien der Gruppe (${JSON.stringify(e3.freigegeben)})`);
    const fg3s = core.bildeFundgruppen([
      { datei: "c.txt", zeile: 1, kategorie: "Rest-Hostname", fund: "Geheim9z", kontext: "x Geheim9z" },
      { datei: "c.txt", zeile: 2, kategorie: "Rest-Geheimnis", fund: "Geheim9z", kontext: "password Geheim9z" }
    ], null);
    assert(fg3s.length === 1 && fg3s[0].sicheresGeheimnis && fg3s[0].aktionen.indexOf("unveraendert") < 0 && core.entscheidungsEintraege(fg3s[0], "ersetzen").geheimnisMuster.length === 1, "Fix 3: mit sicherem Geheimnis gilt die strengste Aktion (nur maskieren)");
    const fg3d = core.bildeFundgruppen([
      { datei: "c.txt", zeile: 1, kategorie: "Rest-Hostname", fund: "werk-nord7", kontext: "werk-nord7" },
      { datei: "c.txt", zeile: 2, kategorie: "Sperrbegriff", fund: "werk-nord7", kontext: "werk-nord7" }
    ], null);
    assert(fg3d.length === 1 && !fg3d[0].kannUnveraendert && fg3d[0].aktionen[0] === "ersetzen", "Fix 3: Sperrbegriff macht die ganze Gruppe nicht freigebbar");
    assert(fg.every(g => g.aktionen.length >= 2), `Fundgruppen: jede Gruppe hat mindestens zwei Aktionen (${fg.map(g => g.art + ":" + g.aktionen.length).join(",")})`);
    const vLauf = core.reprocessFilesWithState([{ path: "b.txt", text: "ArubaOS-CX build id 9f8e7d6c5b4a39281706f5e4d3c2b1a0\n" }], diskRules, core.fuegeEintraegeHinzu({}, eV), new core.AnonState(), {});
    assert(vLauf.ok && vLauf.findings.length === 0 && vLauf.freigegeben === 1, `Verdacht freigegeben: Lauf ohne Restfunde, Freigabe gezählt (${vLauf.findings.length}/${vLauf.freigegeben})`);
    const gS = fg.find(g => g.art === "Sperrbegriff");
    assert(gS.kannErsetzen && !gS.kannUnveraendert && gS.woerter[0] === "Werk-Nord-alt", "Fundgruppen: Sperrbegriff nur ersetzbar, ganzes Wort an der Fundstelle");
    assert(JSON.stringify(gS.aktionen) === '["ersetzen","datei-entfernen"]', "Fundgruppen: Sperrbegriff ersetzen oder Datei entfernen");

    // Entscheidungen: ersetzen -> Eigene Ersetzung, Geheimnis -> Muster mit *****, unverändert -> kategoriegebundene Freigabe
    const eB = core.entscheidungsEintraege(gB, "unveraendert");
    assert(eB.freigegeben.length === 1 && eB.freigegeben[0].kategorie === "Benutzer" && eB.freigegeben[0].wert === "jdoe7" && eB.festeZuordnung.length === 0, "Entscheidung 'Unverändert lassen': Freigabe nur für Kategorie Benutzer");
    const eG = core.entscheidungsEintraege(gG, "ersetzen");
    assert(eG.geheimnisMuster.length === 1 && eG.festeZuordnung.length === 0 && eG.geheimnisMuster[0].ersetzen === "*****", "Entscheidung 'Alle ersetzen' bei Geheimnis: Muster mit *****, keine Zuordnung (Geheimnis nie in der Tabelle)");
    assert(core.entscheidungsEintraege(gG, "unveraendert").freigegeben.length === 0, "Entscheidung: Geheimnis lässt sich nicht freigeben");
    const ctMit = core.fuegeEintraegeHinzu({}, core.entscheidungsEintraege(gB, "ersetzen"));
    assert(ctMit.festeZuordnung.length === 1 && ctMit.festeZuordnung[0].original === "jdoe7", "Entscheidung 'Alle ersetzen': Eigene Ersetzung angelegt");
    const ctZurueck = core.entferneEintraege(ctMit, core.entscheidungsEintraege(gB, "ersetzen"));
    assert(ctZurueck.festeZuordnung.length === 0, "Entscheidung rückgängig: Eigene Ersetzung wieder entfernt");

    // Geheimnis-Muster wirkt in beiden Engines gleich (Dialekt der Regeldatei)
    const gRules = JSON.parse(JSON.stringify(diskRules));
    gRules.geheimnisMuster.push(eG.geheimnisMuster[0]);
    const gOut = core.processText("note Geheim9z here\n", core.buildEngineConfig(gRules, {}), new core.AnonState());
    assert(gOut === "note ***** here\n", `Entscheidung 'Alle ersetzen' bei Geheimnis: Wert wird zu ***** (${JSON.stringify(gOut)})`);
    assert(!forbiddenEscape.test(eG.geheimnisMuster[0].suche), "Entscheidung: erzeugtes Muster nutzt den Regex-Dialekt der Regeldatei (kein \\w, \\d, \\b)");

    // Auftragsebene: wirkt nur im Lauf, dauerhafte Begriffe bleiben unverändert
    const auftrag = [{ eintraege: eB }];
    const lb = core.baueLaufBegriffe({}, auftrag);
    assert(lb.muster["ausnahmen.freigegeben"].length === 1 && core.baueLaufBegriffe({}, []).muster["ausnahmen.freigegeben"] === undefined, "Auftragsebene: Freigabe nur im Lauf mit Auftragsentscheidungen");
    const lauf = core.reprocessFilesWithState([{ path: "a.txt", text: '<Data Name="TargetUserName">jdoe7</Data>\n' }], diskRules, lb, new core.AnonState(), {});
    assert(lauf.ok && lauf.findings.length === 0 && lauf.freigegeben > 0, "Auftragsebene: Lauf mit Freigabe ohne Restfunde, Freigaben gezählt");
    const laufOhne = core.reprocessFilesWithState([{ path: "a.txt", text: '<Data Name="TargetUserName">jdoe7</Data>\n' }], diskRules, {}, new core.AnonState(), {});
    assert(laufOhne.findings.length > 0, "Auftragsebene: ohne Auftragsentscheidung wird der Wert wieder gemeldet");

    // Vorschau-Ausschnitt auch hinter 200 KB
    const gross = Array.from({ length: 30000 }, (_, i) => "filler line number " + i).join("\n");
    assert(gross.length > core.MAX_PREVIEW_CHARS, "Vorschau: Testdatei größer als 200 KB");
    const fen = core.vorschauFenster(gross, 29000);
    assert(fen.start <= 29000 && fen.ende >= 29000 && fen.zeilen.join("\n").length <= core.MAX_PREVIEW_CHARS && fen.gekuerzt && fen.zeilen[29000 - fen.start] === "filler line number 28999", `Vorschau: Ausschnitt um Zeile 29000 (${fen.start}-${fen.ende})`);
    const anfang = core.vorschauFenster(gross, 0);
    assert(anfang.start === 1 && anfang.ende > 1, "Vorschau: ohne Zielzeile ab Zeile 1");
    assert(JSON.stringify(core.geaenderteZeilen("a\nb\nc", "a\nX\nc")) === "[2]", "Vorschau: geänderte Zeilen");
    assert(JSON.stringify(core.ersetzteStellen("ip NET-1.H2 pw *****")) === "[[3,11],[15,20]]", "Vorschau: ersetzte Stellen (Platzhalter und *****)");

    // Dateiliste und Abweichungen vom Standard
    assert(core.dateiAnfangsStatus("x.evtx", true) === "nicht unterstützt" && core.dateiAnfangsStatus("x.dat", true) === "übersprungen" && core.dateiAnfangsStatus("x.log", false) === "bereit", "Dateiliste: Anfangsstatus");
    assert(core.dateiZusammenfassung([{ status: "verarbeitet" }, { status: "verarbeitet" }, { status: "nicht unterstützt" }]) === "3 geladen, 2 verarbeitet, 1 nicht unterstützt", "Dateiliste: Zusammenfassung");
    assert(core.einstellungsAbweichungen({ kategorien: new Set(["ip", "mac"]) }).includes("Benutzernamen werden nicht ersetzt"), "Einstellungen: Abweichung 'Benutzernamen werden nicht ersetzt' sichtbar");
    assert(core.einstellungsAbweichungen({ kategorien: undefined, netzerhaltend: true, ipPrivPub: true }).length === 0, "Einstellungen: Standard ohne Abweichungen");

    // Ersetzungsliste: Anzahl je Platzhalter, erste Stelle, Originale verdeckt
    const ergebnisse = [{ path: "a.txt", anonText: "hostname HOST-1\nip NET-1.H2/24 via NET-1.H1\nHOST-1 HOST-10\n" }, { path: "b.txt", anonText: "peer HOST-2 HOST-1\n1000 2000\n" }];
    const anz = core.zaehlePlatzhalter(ergebnisse);
    assert(anz.get("HOST-1") === 3 && anz.get("HOST-10") === 1 && anz.get("NET-1.H2") === 1 && anz.get("HOST-2") === 1 && !anz.has("1000"), `Ersetzungen: Anzahl je Platzhalter (${JSON.stringify(Array.from(anz))})`);
    const erst = core.erstesVorkommen(ergebnisse, "HOST-2");
    assert(erst && erst.index === 1 && erst.zeile === 1 && core.erstesVorkommen(ergebnisse, "NET-1") === null && core.erstesVorkommen(ergebnisse, "HOST-1").zeile === 1, "Ersetzungen: erste Stelle eines Platzhalters (NET-1 nicht in NET-1.H2)");
    const zeilenHtml = core.renderMappingTableRowsHtml([{ category: "HOST", placeholder: "HOST-1", original: "sw-geheim01" }], { showOriginals: false, anzahl: anz });
    assert(!zeilenHtml.includes("sw-geheim01") && zeilenHtml.includes('class="map-anzahl-cell">3 <button') && zeilenHtml.includes('map-jump-btn" data-ph="HOST-1"'), "Ersetzungen: Original verdeckt, Anzahl mit 'Zur Stelle'");
    assert(core.renderMappingTableRowsHtml([], { anzahl: anz }).includes('colspan="5"') && core.renderMappingTableRowsHtml([], {}).includes('colspan="4"'), "Ersetzungen: Spaltenzahl mit und ohne Anzahl");
    // Einzelne Datei: anonymisierter Name, gleicher Inhalt wie im ZIP
    const ein = core.einzelDateiEintrag({ path: "HOST-1/show-tech.txt", anonText: "hostname HOST-1\n" });
    const zipEin = core.buildReleaseZipEntries([{ path: "HOST-1/show-tech.txt", anonText: "hostname HOST-1\n" }])[0];
    assert(ein.name === "show-tech.txt" && ein.mime === "text/plain" && Buffer.from(ein.data).equals(Buffer.from(zipEin.data)), "Einzeldatei: anonymisierter Dateiname, Inhalt wie im ZIP");
    assert(core.einzelDateiEintrag({ path: "x/HOST-2.json", anonText: "{}" }).mime === "application/json", "Einzeldatei: Dateityp bleibt erhalten");
    // Dateiliste: Namen verdeckt
    assert(core.dateiAnzeigeName({ id: 3, path: "kunde-geheim/sw01.txt" }, false) === "Datei 3" && core.dateiAnzeigeName({ id: 3, path: "kunde-geheim/sw01.txt", anonPath: "FIRMA-1/HOST-1.txt" }, false) === "FIRMA-1/HOST-1.txt" && core.dateiAnzeigeName({ id: 3, path: "kunde-geheim/sw01.txt" }, true) === "kunde-geheim/sw01.txt", "Dateiliste: Namen verdeckt, Original nur auf Wunsch");

    // Oberfläche: keine alert()-Dialoge, Statusmeldungen über aria-live, Originale standardmäßig verdeckt
    const uiTeil = htmlContent.slice(htmlContent.indexOf("// 5. BROWSER-UI STEUERUNG"));
    assert(!/\balert\s*\(/.test(htmlContent), "Oberfläche: keine alert()-Dialoge");
    assert(/id="ablaufStatus"[^>]*aria-live="polite"/.test(htmlContent), "Oberfläche: Statuszeile mit aria-live");
    assert(/<input type="checkbox" id="optOriginalAnzeigen">/.test(htmlContent), "Oberfläche: Originalspalte standardmäßig ausgeblendet");
    assert(!/\.innerHTML\s*=\s*[^"'`;]*\b(?:fund|kontext|original|wert)\b/i.test(uiTeil), "Oberfläche: Werte nie über innerHTML");
  }

  // --- 18. Gemeinsamer Kern & Aufteilung der Seiten (Freitext: tests/run-tests-text.js) ---
  console.log("--- 18. Prüfe gemeinsamen Kern (core/) und Aufteilung der Seiten ---");
  const einbetten = require(path.join(ROOT, "tools", "einbetten.js"));
  const nichtSynchron = einbetten.pruefen();
  assert(nichtSynchron.length === 0, `Gemeinsamer Kern: alle Seiten synchron mit core/ und regeln/ (${nichtSynchron.join(", ") || "ok"})`);
  assert(!htmlContent.includes('id="tab-text"') && !htmlContent.includes("TextPseudonymizer"), "anonymisierer.html enthält keinen Text-Reiter mehr (eigene Seite web/text/text-anonymisierer.html)");
  assert(htmlContent.includes("// >>> core/tabelle/zuordnung.js") && htmlContent.includes("// >>> core/tabelle/krypto.js"), "anonymisierer.html bettet core/tabelle/zuordnung.js und krypto.js ein");

  console.log(`\n========================================`);
  console.log(`TESTERGEBNIS (Node.js): ${passed} bestanden, ${failed} fehlgeschlagen`);
  console.log(`========================================`);
  process.exit(failed > 0 ? 1 : 0);
})();


