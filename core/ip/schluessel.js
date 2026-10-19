  // core/ip/schluessel.js
  // IP-Schlüssel (32 Byte) für den Schlüsselmodus: erzeugen, Kennung bilden, als .anonkey-Datei schreiben und lesen.
  // Die Datei ist im Format ANON-AES256-2 (Passwort) verschlüsselt; anon.ps1 schreibt dasselbe Format
  // (oder ANON-DPAPI-1, nur unter Windows lesbar). Der Schlüssel wird nie im Browser-Speicher abgelegt.
  // Wird mit "node tools/einbetten.js" in web/anonymisierer.html eingebettet; die Tests prüfen die Gleichheit.

  const IP_SCHLUESSEL_TYP = "ANON-IP-SCHLUESSEL-1";
  const IP_SCHLUESSEL_HINWEIS_NEU = "Neuer IP-Schlüssel: IP-Adressen werden anders abgebildet als in früheren Läufen.";
  const IP_HINWEIS_VERFREMDET = "IP-Adressen sind schlüsselbasiert verfremdet, Netze rechnerisch korrekt.";

  function ipSchluesselErzeugen() {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  // Kennung: erste 8 Byte von SHA-256("ANON-IP-KENNUNG|" + Schlüssel) als Hex; erlaubt keinen Rückschluss auf den Schlüssel
  async function ipSchluesselKennung(key) {
    const kopf = new TextEncoder().encode("ANON-IP-KENNUNG|");
    const daten = new Uint8Array(kopf.length + key.length);
    daten.set(kopf, 0);
    daten.set(key, kopf.length);
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", daten));
    daten.fill(0);
    return Array.from(h.slice(0, 8)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function ipSchluesselDateiErstellen(key, password, customIterations) {
    if (!key || key.length !== 32) throw new Error("Der IP-Schlüssel muss 32 Byte lang sein.");
    const inhalt = JSON.stringify({
      typ: IP_SCHLUESSEL_TYP,
      schluessel: bytesToBase64(key),
      kennung: await ipSchluesselKennung(key),
      erstellt: new Date().toISOString()
    });
    return encryptTableAes256V2(inhalt, password, customIterations);
  }

  // Liefert { schluessel: Uint8Array(32), kennung, erstellt }; lehnt unverschlüsselte, fremde und manipulierte Dateien ab
  async function ipSchluesselDateiLesen(text, password) {
    let obj;
    try {
      obj = JSON.parse(String(text));
    } catch (e) {
      throw new Error("Die IP-Schlüsseldatei ist kein gültiges JSON.");
    }
    if (!obj || typeof obj !== "object") throw new Error("Unbekanntes Format der IP-Schlüsseldatei.");
    if (obj.format === "ANON-DPAPI-1") throw new Error("Diese IP-Schlüsseldatei ist mit Windows DPAPI geschützt und nur mit anon.ps1 unter dem erstellenden Windows-Benutzer lesbar.");
    if (obj.format !== "ANON-AES256-2") throw new Error("Die IP-Schlüsseldatei muss im Format ANON-AES256-2 verschlüsselt sein.");
    const inhalt = await decryptTableAes256V2(obj, password);
    if (!inhalt || inhalt.typ !== IP_SCHLUESSEL_TYP) throw new Error("Die Datei enthält keinen IP-Schlüssel.");
    const key = base64ToBytes(String(inhalt.schluessel || ""));
    if (key.length !== 32) throw new Error("Der IP-Schlüssel in der Datei ist nicht 32 Byte lang.");
    const kennung = await ipSchluesselKennung(key);
    if (inhalt.kennung && inhalt.kennung !== kennung) throw new Error("Die Kennung des IP-Schlüssels passt nicht zum Schlüssel (Datei beschädigt).");
    return { schluessel: key, kennung, erstellt: String(inhalt.erstellt || "") };
  }
