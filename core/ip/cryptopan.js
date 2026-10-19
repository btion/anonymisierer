  // core/ip/cryptopan.js
  // Schlüsselbasierte, präfixerhaltende IP-Verfremdung nach Crypto-PAn (Xu, Fan, Ammar, Moon 2002).
  // AES-128 ist eingebettet (nur Verschlüsselung, FIPS-197), damit die Seite ohne externe Bibliothek auskommt.
  // Gemeinsame Testvektoren mit anon.ps1: tests/ip-testvektoren.json
  // Wird mit "node tools/einbetten.js" in web/anonymisierer.html eingebettet; die Tests prüfen die Gleichheit.

  // S-Box nach FIPS-197 aus dem multiplikativen Inversen in GF(2^8) und der affinen Abbildung
  const AES_SBOX = (() => {
    const s = new Uint8Array(256);
    const rotl = (x, n) => ((x << n) | (x >>> (8 - n))) & 0xff;
    let p = 1;
    let q = 1;
    do {
      p = (p ^ ((p << 1) & 0xff) ^ ((p & 0x80) ? 0x1b : 0)) & 0xff;
      q ^= q << 1;
      q ^= q << 2;
      q ^= q << 4;
      q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      s[p] = (q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63) & 0xff;
    } while (p !== 1);
    s[0] = 0x63;
    return s;
  })();

  function aesXtime(x) {
    return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0)) & 0xff;
  }

  // Schlüsselerweiterung AES-128: 16 Byte -> 176 Byte Rundenschlüssel
  function aes128Erweitern(key) {
    if (!key || key.length !== 16) throw new Error("AES-128 erwartet einen Schlüssel mit 16 Byte.");
    const w = new Uint8Array(176);
    w.set(key);
    let rcon = 1;
    for (let i = 16; i < 176; i += 4) {
      let t0 = w[i - 4], t1 = w[i - 3], t2 = w[i - 2], t3 = w[i - 1];
      if (i % 16 === 0) {
        const x = t0;
        t0 = AES_SBOX[t1] ^ rcon;
        t1 = AES_SBOX[t2];
        t2 = AES_SBOX[t3];
        t3 = AES_SBOX[x];
        rcon = aesXtime(rcon);
      }
      w[i] = w[i - 16] ^ t0;
      w[i + 1] = w[i - 15] ^ t1;
      w[i + 2] = w[i - 14] ^ t2;
      w[i + 3] = w[i - 13] ^ t3;
    }
    return w;
  }

  // Ein Block (16 Byte) verschlüsseln; Zustand spaltenweise wie die Eingabe (Index = 4 * Spalte + Zeile)
  function aes128Block(w, input) {
    let s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = input[i] ^ w[i];
    for (let runde = 1; runde <= 10; runde++) {
      const t = new Uint8Array(16);
      for (let c = 0; c < 4; c++) {
        for (let r = 0; r < 4; r++) t[4 * c + r] = AES_SBOX[s[4 * ((c + r) % 4) + r]];
      }
      if (runde < 10) {
        for (let c = 0; c < 4; c++) {
          const a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
          const x0 = aesXtime(a0), x1 = aesXtime(a1), x2 = aesXtime(a2), x3 = aesXtime(a3);
          t[4 * c] = x0 ^ x1 ^ a1 ^ a2 ^ a3;
          t[4 * c + 1] = a0 ^ x1 ^ x2 ^ a2 ^ a3;
          t[4 * c + 2] = a0 ^ a1 ^ x2 ^ x3 ^ a3;
          t[4 * c + 3] = x0 ^ a0 ^ a1 ^ a2 ^ x3;
        }
      }
      for (let i = 0; i < 16; i++) t[i] ^= w[16 * runde + i];
      s = t;
    }
    return s;
  }

  // Crypto-PAn-Schlüssel: 32 Byte; Byte 0-15 AES-Schlüssel, Byte 16-31 ergeben verschlüsselt das Pad
  function cryptoPanSchluessel(key32) {
    if (!key32 || key32.length !== 32) throw new Error("Der IP-Schlüssel muss 32 Byte lang sein.");
    const w = aes128Erweitern(Uint8Array.from(key32.slice(0, 16)));
    const pad = aes128Block(w, Uint8Array.from(key32.slice(16, 32)));
    return { w, pad };
  }

  function ipBit(bytes, i) {
    return (bytes[i >> 3] >> (7 - (i & 7))) & 1;
  }

  function ipBitSetzen(bytes, i, v) {
    const m = 1 << (7 - (i & 7));
    if (v) bytes[i >> 3] |= m;
    else bytes[i >> 3] &= ~m & 0xff;
  }

  // Pseudozufallsbit für die Position pos: die ersten pos Bit der Adresse, Rest aus dem Pad
  function cryptoPanBit(ks, adresse, pos) {
    const inp = Uint8Array.from(ks.pad);
    const voll = pos >> 3;
    for (let j = 0; j < voll; j++) inp[j] = adresse[j];
    const rest = pos & 7;
    if (rest) {
      const m = (0xff << (8 - rest)) & 0xff;
      inp[voll] = (adresse[voll] & m) | (ks.pad[voll] & ~m & 0xff);
    }
    return aes128Block(ks.w, inp)[0] >> 7;
  }

  // Bits von..bis-1 der Adresse (4 oder 16 Byte) abbilden; Bits außerhalb bleiben.
  // erlaubt(praefix, pos): optional, false erzwingt an dieser Stelle "nicht kippen" (Klassen bleiben erhalten).
  // rueck = true kehrt die Abbildung um (aus den bereits zurückgewonnenen Bits folgt das nächste Kippbit).
  function cryptoPanAbbilden(ks, adresse, von, bis, erlaubt, rueck) {
    const ein = Uint8Array.from(adresse);
    const aus = Uint8Array.from(adresse);
    const basis = rueck ? aus : ein;
    for (let pos = von; pos < bis; pos++) {
      let kipp = cryptoPanBit(ks, basis, pos);
      if (kipp && erlaubt && !erlaubt(basis, pos)) kipp = 0;
      ipBitSetzen(aus, pos, ipBit(ein, pos) ^ kipp);
    }
    return aus;
  }

  // Original-Crypto-PAn über alle Bits (für die veröffentlichten Testvektoren)
  function cryptoPanStandard(ks, adresse, rueck) {
    return cryptoPanAbbilden(ks, adresse, 0, adresse.length * 8, null, !!rueck);
  }
