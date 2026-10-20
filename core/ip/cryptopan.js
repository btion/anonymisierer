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
    return { w, pad, memo: new Map() };
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

  // Klassenmodus: eindeutige AES-Eingabe je Stelle: (erste pos Bit der Adresse, dann ein 1-Bit, dann Nullen) XOR Pad.
  // Im Original-Crypto-PAn sind die Eingaben zweier Stellen gleich, wenn das Adressbit dem Pad-Bit gleicht; die Kippbits
  // sind dann gekoppelt (ein Oktett bliebe bei rund 7 % der Schlüssel unverändert). Die Polsterung ist umkehrbar eindeutig.
  function cryptoPanBitGetrennt(ks, adresse, pos) {
    const inp = new Uint8Array(16);
    const voll = pos >> 3;
    for (let j = 0; j < voll; j++) inp[j] = adresse[j];
    const rest = pos & 7;
    if (rest) inp[voll] = adresse[voll] & ((0xff << (8 - rest)) & 0xff);
    inp[voll] |= 0x80 >> rest;
    for (let j = 0; j < 16; j++) inp[j] ^= ks.pad[j];
    return aes128Block(ks.w, inp)[0] >> 7;
  }

  // Bits von..bis-1 der Adresse (4 oder 16 Byte) abbilden; Bits außerhalb bleiben.
  // erlaubt(praefix, pos): optional, false erzwingt an dieser Stelle "nicht kippen" (Klassen bleiben erhalten).
  // rueck = true kehrt die Abbildung um (aus den bereits zurückgewonnenen Bits folgt das nächste Kippbit).
  // getrennt = true: eindeutige AES-Eingabe je Stelle (Klassenmodus), sonst Original-Crypto-PAn
  function cryptoPanAbbilden(ks, adresse, von, bis, erlaubt, rueck, getrennt) {
    const ein = Uint8Array.from(adresse);
    const aus = Uint8Array.from(adresse);
    const basis = rueck ? aus : ein;
    for (let pos = von; pos < bis; pos++) {
      let kipp = getrennt ? cryptoPanBitGetrennt(ks, basis, pos) : cryptoPanBit(ks, basis, pos);
      if (kipp && erlaubt && !erlaubt(basis, pos)) kipp = 0;
      ipBitSetzen(aus, pos, ipBit(ein, pos) ^ kipp);
    }
    return aus;
  }

  // Original-Crypto-PAn über alle Bits (für die veröffentlichten Testvektoren)
  function cryptoPanStandard(ks, adresse, rueck) {
    return cryptoPanAbbilden(ks, adresse, 0, adresse.length * 8, null, !!rueck);
  }

  // --------------------------------------------------------------------------
  // Adressklassen: Blöcke bleiben erhalten, öffentliche Adressen landen nie in einem Sonderbereich
  //   fest        unverändert (0/8, 127/8, 224/4, 240/4; ::, ::1, ff00::/8)
  //   privat      Blockpräfix bleibt, Bits bis zur festen Grenze (/24, IPv6 /120) schlüsselbasiert, Rest bleibt
  //   block       Blockpräfix bleibt, alle übrigen Bits schlüsselbasiert (Dokumentations- und Sondernetze)
  //   oeffentlich Bits bis zur festen Grenze schlüsselbasiert, ohne in einen der Blöcke oben zu wechseln
  // --------------------------------------------------------------------------
  const IP4_KLASSEN = [
    ["0.0.0.0", 8, "fest"], ["127.0.0.0", 8, "fest"], ["224.0.0.0", 4, "fest"], ["240.0.0.0", 4, "fest"],
    ["10.0.0.0", 8, "privat"], ["100.64.0.0", 10, "privat"], ["169.254.0.0", 16, "privat"], ["172.16.0.0", 12, "privat"], ["192.168.0.0", 16, "privat"],
    ["192.0.0.0", 24, "block"], ["192.0.2.0", 24, "block"], ["192.88.99.0", 24, "block"], ["198.18.0.0", 15, "block"], ["198.51.100.0", 24, "block"], ["203.0.113.0", 24, "block"]
  ];
  const IP6_KLASSEN = [
    ["::", 128, "fest"], ["::1", 128, "fest"], ["ff00::", 8, "fest"],
    ["fe80::", 64, "privat"], ["fc00::", 8, "privat"], ["fd00::", 8, "privat"],
    ["fe80::", 10, "block"], ["fec0::", 10, "block"], ["2001:db8::", 32, "block"], ["2001::", 23, "block"], ["2002::", 16, "block"], ["3fff::", 20, "block"],
    ["::", 8, "block"], ["100::", 64, "block"],
    // außerhalb von 2000::/3 (nicht vergeben): erstes Viertel bleibt
    ["::", 3, "block16"], ["4000::", 2, "block16"], ["8000::", 1, "block16"]
  ];
  const IP_GRENZE = { 4: 24, 16: 120 };

  function ipBits(bytes, n) {
    let s = "";
    for (let i = 0; i < n; i++) s += ipBit(bytes, i);
    return s;
  }

  function ip4Lesen(text) {
    const t = String(text).split(".");
    if (t.length !== 4) return null;
    const b = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      if (!/^(?:0|[1-9][0-9]{0,2})$/.test(t[i]) || Number(t[i]) > 255) return null;
      b[i] = Number(t[i]);
    }
    return b;
  }

  function ip4Text(b) {
    return b[0] + "." + b[1] + "." + b[2] + "." + b[3];
  }

  // IPv4 auch mit führenden Nullen in den Oktetten (010.000.000.013); null, wenn keine IPv4
  function ip4LesenNullen(text) {
    const t = String(text).split(".");
    if (t.length !== 4) return null;
    const b = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      if (!/^[0-9]{1,3}$/.test(t[i]) || Number(t[i]) > 255) return null;
      b[i] = Number(t[i]);
    }
    return b;
  }

  // IPv6 in 16 Byte (Kurz- und Langform, auch gemischt mit eingebetteter IPv4 wie ::ffff:192.0.2.1; ohne Zonen-Index)
  function ip6Lesen(text) {
    let t = String(text).toLowerCase();
    if (t.indexOf(".") >= 0) {
      const p = t.lastIndexOf(":");
      const v4 = p >= 0 ? ip4LesenNullen(t.slice(p + 1)) : null;
      if (!v4) return null;
      t = t.slice(0, p + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ":" + ((v4[2] << 8) | v4[3]).toString(16);
    }
    if (!/^[0-9a-f:]+$/.test(t) || t.indexOf(":::") >= 0) return null;
    const teile = t.split("::");
    if (teile.length > 2) return null;
    const links = teile[0] ? teile[0].split(":") : [];
    const rechts = teile.length === 2 && teile[1] ? teile[1].split(":") : [];
    if (teile.length === 1 && links.length !== 8) return null;
    if (teile.length === 2 && links.length + rechts.length > 7) return null;
    const gruppen = links.concat(new Array(8 - links.length - rechts.length).fill("0"), rechts);
    const b = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      if (!/^[0-9a-f]{1,4}$/.test(gruppen[i])) return null;
      const v = parseInt(gruppen[i], 16);
      b[2 * i] = v >> 8;
      b[2 * i + 1] = v & 0xff;
    }
    return b;
  }

  // Ausgabe nach RFC 5952: Kleinbuchstaben, ohne führende Nullen, längste Nullfolge (ab 2 Gruppen) als ::
  function ip6Text(b) {
    const g = [];
    for (let i = 0; i < 8; i++) g.push((b[2 * i] << 8) | b[2 * i + 1]);
    let best = -1, bestLen = 0;
    for (let i = 0; i < 8;) {
      if (g[i] !== 0) { i++; continue; }
      let j = i;
      while (j < 8 && g[j] === 0) j++;
      if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
      i = j;
    }
    const h = g.map(v => v.toString(16));
    if (best < 0) return h.join(":");
    return h.slice(0, best).join(":") + "::" + h.slice(best + bestLen).join(":");
  }

  let ipKlassenCache = null;
  function ipKlassenListe(n) {
    if (!ipKlassenCache) {
      const bau = (liste, lesen, bytes) => liste.map(([a, l, art]) => ({ bits: ipBits(lesen(a), l), laenge: l, art }));
      ipKlassenCache = { 4: bau(IP4_KLASSEN, ip4Lesen), 16: bau(IP6_KLASSEN, ip6Lesen), sig4: new Map(), sig16: new Map() };
    }
    return ipKlassenCache[n];
  }

  function ipKlasse(bytes) {
    const n = bytes.length;
    const bits = ipBits(bytes, n * 8);
    for (const k of ipKlassenListe(n)) {
      if (bits.startsWith(k.bits)) {
        if (k.art === "block16") return { art: "block", laenge: 16 };
        return { art: k.art, laenge: k.laenge };
      }
    }
    return { art: "oeffentlich", laenge: 0 };
  }

  // Struktur eines Teilbaums: "P" nur öffentlich, "S" vollständig in einem Block, sonst beide Hälften
  function ipStruktur(n, bits) {
    const memo = ipKlassenCache["sig" + n];
    let r = memo.get(bits);
    if (r !== undefined) return r;
    const liste = ipKlassenListe(n);
    if (liste.some(k => k.laenge <= bits.length && bits.startsWith(k.bits))) r = "S";
    else if (!liste.some(k => k.laenge > bits.length && k.bits.startsWith(bits))) r = "P";
    else r = "(" + ipStruktur(n, bits + "0") + ipStruktur(n, bits + "1") + ")";
    memo.set(bits, r);
    return r;
  }

  // Kippen nur, wenn beide Hälften gleich aufgebaut sind: dann bleibt öffentlich immer öffentlich
  function ipOeffentlichErlaubt(praefix, pos) {
    const n = praefix.length;
    ipKlassenListe(n);
    const bits = ipBits(praefix, pos);
    return ipStruktur(n, bits + "0") === ipStruktur(n, bits + "1");
  }

  // IPv6 mit eingebetteter IPv4: ::ffff:0:0/96 (IPv4-mapped) und 64:ff9b::/96 (NAT64); die IPv4 steht in Byte 12-15
  function ipEingebetteteV4(bytes) {
    if (!bytes || bytes.length !== 16) return false;
    const mapped = bytes.slice(0, 10).every(x => x === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
    const nat64 = bytes[0] === 0 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && bytes.slice(4, 12).every(x => x === 0);
    return mapped || nat64;
  }

  // IPv6: Schnittstellenkennung mit Nullen in den oberen 48 Bit (::1, ::fe, ::254) bleibt ganz erhalten.
  // Damit keine andere Kennung dorthin abgebildet wird, kippt auf dem Nullpfad (Bit 64 bis 111) kein Bit.
  function ipKleineKennung(bytes) {
    return bytes.length === 16 && bytes.slice(8, 14).every(x => x === 0);
  }

  function ipKennungErlaubt(praefix, pos) {
    if (praefix.length !== 16 || pos < 64 || pos >= 112) return true;
    for (let i = 64; i < pos; i++) if (ipBit(praefix, i)) return true;
    return false;
  }

  // Klassenerhaltende Abbildung einer Adresse (4 oder 16 Byte); rueck = Umkehrung
  function ipVerfremden(ks, bytes, rueck) {
    const n = bytes.length;
    const schl = (rueck ? "r" : "v") + n + ":" + Array.from(bytes).join(",");
    const vorher = ks.memo.get(schl);
    if (vorher) return Uint8Array.from(vorher);
    const k = ipKlasse(bytes);
    // IPv6: kleine Schnittstellenkennung bleibt (Bereich endet bei Bit 64), sonst Nullpfad sperren
    const klein = ipKleineKennung(bytes);
    const kennung = n === 16 ? ipKennungErlaubt : null;
    const ende = (voll) => (klein ? Math.min(64, voll) : voll);
    let aus;
    if (k.art === "fest") aus = Uint8Array.from(bytes);
    else if (k.art === "privat") aus = cryptoPanAbbilden(ks, bytes, k.laenge, ende(IP_GRENZE[n]), kennung, !!rueck, true);
    else if (k.art === "block") aus = cryptoPanAbbilden(ks, bytes, k.laenge, ende(n * 8), kennung, !!rueck, true);
    else aus = cryptoPanAbbilden(ks, bytes, 0, ende(IP_GRENZE[n]), n === 16 ? (p, pos) => ipOeffentlichErlaubt(p, pos) && ipKennungErlaubt(p, pos) : ipOeffentlichErlaubt, !!rueck, true);
    ks.memo.set(schl, Uint8Array.from(aus));
    return aus;
  }

  // Textform: "192.0.2.10" oder "2001:db8::1"; praefix (Zahl oder null) aus "/n".
  // Bei bekannter Präfixlänge werden Netzadresse und Broadcast kanonisch ausgegeben (Host-Bits 0 bzw. 1).
  // Ergebnis null: keine gültige Adresse. Adressen der Klasse "fest" bleiben wörtlich.
  function ipTextVerfremden(ks, text, praefix, rueck) {
    const v4 = ip4Lesen(text);
    const bytes = v4 || ip6Lesen(text);
    if (!bytes) return null;
    if (ipKlasse(bytes).art === "fest") return String(text);
    const aus = ipVerfremden(ks, bytes, rueck);
    const n = bytes.length * 8;
    if (praefix !== null && praefix !== undefined && praefix >= 0 && praefix < n) {
      let null0 = true, eins = true;
      for (let i = praefix; i < n; i++) {
        if (ipBit(bytes, i)) null0 = false; else eins = false;
      }
      if (null0 || eins) for (let i = praefix; i < n; i++) ipBitSetzen(aus, i, eins ? 1 : 0);
    }
    return v4 ? ip4Text(aus) : ip6Text(aus);
  }
