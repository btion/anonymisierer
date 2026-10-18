// Browser-Test (headless Chrome/Chromium) für web/anonymisierer.html: führt die echten UI-Handler aus
// und prüft, dass jede relevante Änderung die Exportfreigabe ungültig macht.
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

// Testskript, das in eine Kopie der Seite eingefügt wird (nutzt nur die vorhandenen Bedienelemente)
const PROBE = `<script>
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
  for (let i = 0; i < 200 && !/bereit/.test(info.textContent); i++) await warte(50);
};
async function lauf() {
  const banner = document.getElementById("auditBanner");
  banner.textContent = "";
  document.getElementById("btnRunAnon").click();
  for (let i = 0; i < 200 && !/Prüfergebnis/.test(banner.textContent); i++) await warte(50);
  await warte(50);
}
window.addEventListener("load", async () => {
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

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "anon-browser-"));
try {
  const seite = path.join(tmp, "seite.html");
  fs.writeFileSync(seite, fs.readFileSync(HTML_PATH, "utf8").replace("</body>", PROBE), "utf8");
  const r = spawnSync(browser, ["--headless=new", "--disable-gpu", "--no-first-run", "--no-sandbox",
    `--user-data-dir=${path.join(tmp, "profil")}`, "--virtual-time-budget=60000", "--dump-dom",
    "file://" + seite.replace(/\\/g, "/")], { encoding: "utf8", timeout: 120000 });
  const m = /<pre id="__probe">([\s\S]*?)<\/pre>/.exec(r.stdout || "");
  assert(Boolean(m), "Browser-Test: Ergebnis des Testskripts gefunden");
  if (m) {
    const daten = JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
    assert(daten.fehler.length === 0, `Browser-Test: keine JavaScript-Fehler (${daten.fehler.join(" | ")})`);
    for (const st of daten.schritte) {
      const erwartet = st.name === "lauf";
      assert(st.zip === erwartet && st.kopie === erwartet,
        `Exportfreigabe nach '${st.name}': ZIP=${st.zip}, Kopieren=${st.kopie} (erwartet ${erwartet})`);
    }
    assert(daten.schritte.length === 13, `Browser-Test: alle 13 Schritte ausgeführt (${daten.schritte.length})`);
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(`\n========================================`);
console.log(`TESTERGEBNIS (Browser, ${path.basename(browser)}): ${passed} bestanden, ${failed} fehlgeschlagen`);
console.log(`========================================`);
process.exit(failed > 0 ? 1 : 0);
