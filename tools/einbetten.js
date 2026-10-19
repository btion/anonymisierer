// Bettet den gemeinsamen Kern (core/), das Regelwerk (regeln/anon-regeln.json) und die
// Schlüsselwortliste der Strukturvorlage (regeln/strukturvorlage.json) in die
// Offline-Seiten ein. Die Seiten bleiben einzelne HTML-Dateien ohne externe Skripte.
//
//   node tools/einbetten.js            schreibt alle Seiten neu
//   node tools/einbetten.js --pruefen  meldet Abweichungen, Exit-Code 1 wenn nicht synchron
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const REGELN = "regeln/anon-regeln.json";
const STRUKTUR = "regeln/strukturvorlage.json";

// Seite -> eingebettete Kerndateien (Reihenfolge wie in der Seite)
const SEITEN = {
  "web/anonymisierer.html": ["core/tabelle/zuordnung.js", "core/tabelle/krypto.js", "core/ip/cryptopan.js", "core/ip/schluessel.js"],
  "web/text/text-anonymisierer.html": ["core/text/text-engine.js", "core/tabelle/zuordnung.js", "core/tabelle/krypto.js"]
};

function lesen(rel) {
  return fs.readFileSync(path.join(ROOT, rel), "utf8");
}

// core/text/text-engine.js ist ein UMD-Modul; eingebettet wird nur der Rumpf der Factory-Funktion
function kernInhalt(rel) {
  const t = lesen(rel);
  if (rel === "core/text/text-engine.js") {
    const kopf = "function () {\n";
    const a = t.indexOf(kopf);
    const b = t.lastIndexOf("\n});");
    if (a < 0 || b < 0) throw new Error(`${rel}: Factory-Rumpf nicht gefunden`);
    return t.slice(a + kopf.length, b) + "\n";
  }
  return t;
}

function startMarke(rel) {
  return `  // >>> ${rel} (eingebettet, nicht hier bearbeiten: node tools/einbetten.js)\n`;
}

function endMarke(rel) {
  return `  // <<< ${rel}`;
}

function einbetten(html, rel, seite) {
  const start = startMarke(rel);
  const a = html.indexOf(start);
  const b = html.indexOf(endMarke(rel), a);
  if (a < 0 || b < 0) throw new Error(`${seite}: Marken für ${rel} fehlen`);
  return html.slice(0, a + start.length) + kernInhalt(rel) + html.slice(b);
}

function regelnEinbetten(html) {
  const json = JSON.parse(lesen(REGELN));
  const zeilen = JSON.stringify(json, null, 2).split("\n");
  const block = "  const DEFAULT_RULES = " + zeilen.map((z, i) => (i === 0 ? z : "  " + z)).join("\n") + ";";
  const a = html.indexOf("  const DEFAULT_RULES = {");
  const b = html.indexOf("\n  };", a);
  if (a < 0 || b < 0) throw new Error("DEFAULT_RULES nicht gefunden");
  return html.slice(0, a) + block + html.slice(b + "\n  };".length);
}

function strukturVorlageEinbetten(html) {
  const json = JSON.parse(lesen(STRUKTUR));
  const zeilen = JSON.stringify(json, null, 2).split("\n");
  const block = "  const STRUKTUR_VORLAGE = " + zeilen.map((z, i) => (i === 0 ? z : "  " + z)).join("\n") + ";";
  const marke = "  const STRUKTUR_VORLAGE = ";
  const a = html.indexOf(marke);
  if (a < 0) throw new Error("STRUKTUR_VORLAGE nicht gefunden");
  const b = html.indexOf(";\n", a);
  return html.slice(0, a) + block + html.slice(b + 1);
}

function sollStand(seite) {
  let html = lesen(seite);
  for (const rel of SEITEN[seite]) html = einbetten(html, rel, seite);
  if (seite === "web/anonymisierer.html") html = strukturVorlageEinbetten(regelnEinbetten(html));
  return html;
}

// Liefert die Seiten, deren eingebetteter Inhalt nicht dem Kern entspricht
function pruefen() {
  return Object.keys(SEITEN).filter(seite => sollStand(seite) !== lesen(seite));
}

function schreiben() {
  for (const seite of Object.keys(SEITEN)) {
    const neu = sollStand(seite);
    if (neu !== lesen(seite)) {
      fs.writeFileSync(path.join(ROOT, seite), neu, "utf8");
      console.log(`aktualisiert: ${seite}`);
    }
  }
}

module.exports = { SEITEN, pruefen, kernInhalt };

if (require.main === module) {
  if (process.argv.includes("--pruefen")) {
    const abweichend = pruefen();
    if (abweichend.length > 0) {
      console.error("Nicht synchron: " + abweichend.join(", ") + " (node tools/einbetten.js ausführen)");
      process.exit(1);
    }
    console.log("Alle Seiten synchron mit core/ und regeln/.");
  } else {
    schreiben();
  }
}
