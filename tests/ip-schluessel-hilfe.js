// Hilfe für tests/run-tests.ps1: liest bzw. erstellt eine .anonkey-Datei mit dem Kern aus web/anonymisierer.html
// (Gegenprobe der Formate zwischen anon.ps1 und Browser). Nur für Tests mit Testpasswörtern.
//   node tests/ip-schluessel-hilfe.js lesen <datei> <passwort>      gibt die Kennung aus
//   node tests/ip-schluessel-hilfe.js erstellen <datei> <passwort>  schreibt einen neuen Schlüssel, gibt die Kennung aus
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const html = fs.readFileSync(path.join(__dirname, "..", "web", "anonymisierer.html"), "utf8");
const sandbox = {
  module: { exports: {} }, TextEncoder, TextDecoder, Uint8Array, crypto: require("crypto").webcrypto,
  atob: (b) => Buffer.from(b, "base64").toString("binary"), btoa: (b) => Buffer.from(b, "binary").toString("base64"), console
};
vm.runInNewContext(html.match(/<script id="anon-core-script">([\s\S]*?)<\/script>/)[1], sandbox);
const core = sandbox.module.exports;
(async () => {
  const [befehl, datei, passwort] = process.argv.slice(2);
  if (befehl === "lesen") {
    const k = await core.ipSchluesselDateiLesen(fs.readFileSync(datei, "utf8"), passwort);
    process.stdout.write(k.kennung + "\n");
  } else if (befehl === "erstellen") {
    const key = core.ipSchluesselErzeugen();
    fs.writeFileSync(datei, await core.ipSchluesselDateiErstellen(key, passwort, 2000), "utf8");
    process.stdout.write((await core.ipSchluesselKennung(key)) + "\n");
  } else {
    throw new Error("Befehl: lesen | erstellen");
  }
})().catch((e) => { process.stderr.write(String(e.message) + "\n"); process.exit(1); });
