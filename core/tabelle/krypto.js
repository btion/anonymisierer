  // core/tabelle/krypto.js
  // Tabellenverschlüsselung ANON-AES256-2 (Standard), Laden von ANON-AES256-1 und ANON-WEBCRYPTO-AESGCM-1.
  // Gemeinsamer Kern für web/anonymisierer.html und web/text/text-anonymisierer.html.
  // Wird mit "node tools/einbetten.js" in beide Seiten eingebettet; die Tests prüfen die Gleichheit.

  function bytesToBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    if (!b64) return new Uint8Array(0);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  const PBKDF2_DEFAULT_ITERATIONS = 600000;
  const PBKDF2_LEGACY_ITERATIONS = 100000;
  const MIN_PASSWORD_LENGTH = 12;
  const PBKDF2_MAX_ITERATIONS = 5000000;

  function checkTableIterations(iterations, format) {
    if (!Number.isInteger(iterations) || iterations <= 0) {
      throw new Error(`Ungültige oder fehlende Iterationszahl in ${format}.`);
    }
    if (iterations > PBKDF2_MAX_ITERATIONS) {
      throw new Error("Zuordnungstabelle abgelehnt: Iterationszahl über dem Höchstwert von 5.000.000.");
    }
  }

  function validatePasswordMinLength(password) {
    if (!password || String(password).length < MIN_PASSWORD_LENGTH) {
      throw new Error(`Das Passwort für die Tabellenverschlüsselung muss mindestens ${MIN_PASSWORD_LENGTH} Zeichen lang sein.`);
    }
  }

  function buildAes256V2MacInput(iterations, salt, iv, cipher) {
    const enc = new TextEncoder();
    const headerBytes = enc.encode(`ANON-AES256-2|${iterations}`);
    const macInput = new Uint8Array(headerBytes.length + salt.length + iv.length + cipher.length);
    let offset = 0;
    macInput.set(headerBytes, offset); offset += headerBytes.length;
    macInput.set(salt, offset); offset += salt.length;
    macInput.set(iv, offset); offset += iv.length;
    macInput.set(cipher, offset);
    return macInput;
  }

  async function deriveAes256V2Subkeys(password, salt, iterations, kdf) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const masterBits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: kdf === "PBKDF2-SHA256" ? "SHA-256" : "SHA-1" },
      keyMaterial,
      256
    );
    const masterHmacKey = await crypto.subtle.importKey(
      "raw",
      masterBits,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const encKeyBytes = new Uint8Array(await crypto.subtle.sign("HMAC", masterHmacKey, enc.encode("enc")));
    const macKeyBytes = new Uint8Array(await crypto.subtle.sign("HMAC", masterHmacKey, enc.encode("mac")));
    const aesKey = await crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
    const macKey = await crypto.subtle.importKey("raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return { aesKey, macKey };
  }

  // Standardformat der Browser-Variante (lesbar von anon.ps1); kdf: "PBKDF2-SHA256" (Standard) oder "PBKDF2-SHA1"
  async function encryptTableAes256V2(plainJsonStr, password, customIterations, kdfName) {
    validatePasswordMinLength(password);
    const kdf = kdfName === "PBKDF2-SHA1" ? "PBKDF2-SHA1" : "PBKDF2-SHA256";
    const iterations = (typeof customIterations === "number" && customIterations > 0)
      ? customIterations
      : PBKDF2_DEFAULT_ITERATIONS;
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const { aesKey, macKey } = await deriveAes256V2Subkeys(password, salt, iterations, kdf);
    const cipherBuf = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, enc.encode(plainJsonStr));
    const cipher = new Uint8Array(cipherBuf);
    const macInput = buildAes256V2MacInput(iterations, salt, iv, cipher);
    const macBytes = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, macInput));
    return JSON.stringify({
      format: "ANON-AES256-2",
      kdf,
      iterations,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      hmac: bytesToBase64(macBytes),
      daten: bytesToBase64(cipher)
    }, null, 2);
  }

  async function decryptTableAes256V2(rawTextOrObj, password, onWarning) {
    const obj = typeof rawTextOrObj === "string" ? JSON.parse(rawTextOrObj) : rawTextOrObj;
    if (!obj || (obj.format !== "ANON-AES256-2" && obj.format !== "ANON-AES256-1")) {
      return obj;
    }
    if (!password) {
      throw new Error("Bitte Passwort für die verschlüsselte Zuordnungstabelle eingeben.");
    }
    if (obj.format === "ANON-AES256-2") {
      const iterProp = obj.iterations !== undefined ? obj.iterations : obj.iterationen;
      const iterations = Number(iterProp);
      checkTableIterations(iterations, "ANON-AES256-2");
      const kdf = obj.kdf === undefined ? "PBKDF2-SHA1" : obj.kdf;
      if (kdf !== "PBKDF2-SHA1" && kdf !== "PBKDF2-SHA256") {
        throw new Error("Unbekanntes Ableitungsverfahren in ANON-AES256-2.");
      }
      if (!obj.hmac || typeof obj.hmac !== "string") {
        throw new Error("Fehlender HMAC in ANON-AES256-2.");
      }
      const salt = base64ToBytes(obj.salt);
      const iv = base64ToBytes(obj.iv);
      const cipher = base64ToBytes(obj.daten);
      const expectedMac = base64ToBytes(obj.hmac);
      if (expectedMac.length !== 32) {
        throw new Error("Ungültige HMAC-Länge in ANON-AES256-2 (erwartet: 32 Bytes).");
      }
      if (salt.length < 8 || iv.length !== 16) {
        throw new Error("Ungültiges Salt oder IV in ANON-AES256-2.");
      }
      const { aesKey, macKey } = await deriveAes256V2Subkeys(password, salt, iterations, kdf);
      const macInput = buildAes256V2MacInput(iterations, salt, iv, cipher);
      const actualMac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, macInput));
      let diff = 0;
      for (let i = 0; i < 32; i++) {
        diff |= (actualMac[i] ^ expectedMac[i]);
      }
      if (diff !== 0) {
        throw new Error("HMAC-Prüfung fehlgeschlagen (Passwort falsch oder Datei manipuliert).");
      }
      const plainBuf = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, cipher);
      const parsed = JSON.parse(new TextDecoder("utf-8").decode(plainBuf));
      parsed._protectionMode = "PASSWORD";
      parsed._loadedFormat = "ANON-AES256-2";
      return parsed;
    }
    // Legacy ANON-AES256-1 (ladbar mit Warnung, wird beim Speichern auf ANON-AES256-2 gehoben)
    const warnMsg = "Veraltetes Tabellenformat ANON-AES256-1 geladen. Beim nächsten Speichern wird automatisch auf ANON-AES256-2 aktualisiert.";
    if (typeof onWarning === "function") onWarning(warnMsg);
    else if (typeof console !== "undefined" && console.warn) console.warn(warnMsg);

    const iterProp = obj.iterations !== undefined ? obj.iterations : obj.iterationen;
    const iterations = iterProp !== undefined ? Number(iterProp) : PBKDF2_LEGACY_ITERATIONS;
    checkTableIterations(iterations, "ANON-AES256-1");
    if (!obj.hmac || typeof obj.hmac !== "string") {
      throw new Error("Fehlender HMAC in ANON-AES256-1.");
    }
    const salt = base64ToBytes(obj.salt);
    const iv = base64ToBytes(obj.iv);
    const cipher = base64ToBytes(obj.daten);
    const expectedMac = base64ToBytes(obj.hmac);
    if (expectedMac.length !== 32) {
      throw new Error("Ungültige HMAC-Länge in ANON-AES256-1.");
    }
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const keyBits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-1" }, keyMaterial, 256);
    const macKey = await crypto.subtle.importKey("raw", keyBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const actualMac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, cipher));
    let diff = 0;
    for (let i = 0; i < 32; i++) {
      diff |= (actualMac[i] ^ expectedMac[i]);
    }
    if (diff !== 0) {
      throw new Error("HMAC/Passwort-Prüfung für Zuordnungstabelle fehlgeschlagen.");
    }
    const aesKey = await crypto.subtle.importKey("raw", keyBits, { name: "AES-CBC" }, false, ["decrypt"]);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, cipher);
    const parsed = JSON.parse(new TextDecoder("utf-8").decode(plainBuf));
    parsed._protectionMode = "PASSWORD";
    parsed._loadedFormat = "ANON-AES256-1";
    return parsed;
  }

  async function encryptTableWebCrypto(plainJsonStr, password, customIterations) {
    validatePasswordMinLength(password);
    const iterations = (typeof customIterations === "number" && customIterations > 0)
      ? customIterations
      : PBKDF2_DEFAULT_ITERATIONS;
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plainJsonStr));
    return JSON.stringify({
      format: "ANON-WEBCRYPTO-AESGCM-1",
      kdf: "PBKDF2-SHA256",
      iterations,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      daten: bytesToBase64(new Uint8Array(cipherBuf))
    }, null, 2);
  }

  async function decryptTableWebCrypto(rawText, password, onWarning) {
    const obj = JSON.parse(rawText);
    if (obj && (obj.format === "ANON-AES256-2" || obj.format === "ANON-AES256-1")) {
      return decryptTableAes256V2(obj, password, onWarning);
    }
    if (obj && obj.format === "ANON-WEBCRYPTO-AESGCM-1") {
      if (!password) throw new Error("Bitte Passwort für die verschlüsselte Zuordnungstabelle eingeben.");
      const hasExplicitIter = obj.iterations !== undefined || obj.iterationen !== undefined;
      const iterations = hasExplicitIter ? Number(obj.iterations !== undefined ? obj.iterations : obj.iterationen) : PBKDF2_LEGACY_ITERATIONS;
      checkTableIterations(iterations, "ANON-WEBCRYPTO-AESGCM-1");
      const enc = new TextEncoder();
      const salt = base64ToBytes(obj.salt);
      const iv = base64ToBytes(obj.iv);
      const cipher = base64ToBytes(obj.daten);
      const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
      const parsed = JSON.parse(new TextDecoder("utf-8").decode(plainBuf));
      parsed._protectionMode = "PASSWORD";
      parsed._loadedFormat = "ANON-WEBCRYPTO-AESGCM-1";
      return parsed;
    }
    return obj;
  }
