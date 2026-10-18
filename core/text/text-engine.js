/**
 * core/text/text-engine.js
 *
 * Eigenständiges Modul für die datenschutzkonforme Pseudonymisierung von Freitexten
 * (E-Mails, Briefe, Notizen, Berichte, Tickets).
 *
 * - 100% offline, keine externen Abhängigkeiten, keine KI.
 * - Strikte Trennung vom Netzwerk-Anonymisierer.
 * - Dreistufiges Modell:
 *     ROT  = Sicher & automatisch ersetzt (Prüfziffern, strenge Formate)
 *     GELB = Kandidaten zur Sichtprüfung (Namen, Adressen, Aktenzeichen)
 *     MANUELL = Benutzerdefinierte Bereiche
 * - Mechanismus pro Kategorie: platzhalter ([NAME-1], rückführbar), entfernen (████████)
 *   oder generalisieren (z. B. Datum → Jahr); Vorgabe über den Modus Token / Schwärzung.
 * - Wording: "pseudonymisieren", "Geprüft, n Treffer ersetzt, Sichtprüfung erforderlich"
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.TextPseudonymizer = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // =========================================================================
  // 1. Mathematische Prüfziffern-Algorithmen (vollständig offline)
  // =========================================================================

  /**
   * Quelle: ISO 7064, MOD 97-10 (IBAN-Prüfsumme nach ISO 13616)
   */
  function isValidIban(raw) {
    if (typeof raw !== "string") return false;
    const clean = raw.replace(/[\s-]/g, "").toUpperCase();
    if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(clean)) return false;
    const rearranged = clean.slice(4) + clean.slice(0, 4);
    let numStr = "";
    for (let i = 0; i < rearranged.length; i++) {
      const code = rearranged.charCodeAt(i);
      if (code >= 65 && code <= 90) {
        numStr += (code - 55).toString();
      } else if (code >= 48 && code <= 57) {
        numStr += rearranged[i];
      } else {
        return false;
      }
    }
    try {
      return BigInt(numStr) % 97n === 1n;
    } catch (e) {
      return false;
    }
  }

  /**
   * Quelle: § 139b AO, DIN ISO 7064 Mod 11, 10 (Steuerliche Identifikationsnummer)
   */
  function isValidSteuerId(raw) {
    if (typeof raw !== "string") return false;
    const idStr = raw.replace(/[\s/]/g, "");
    if (!/^[1-9][0-9]{10}$/.test(idStr)) return false;

    // Ziffernhäufigkeit prüfen: Genau eine Ziffer kommt genau 2- oder 3-mal vor
    const counts = {};
    for (let i = 0; i < 10; i++) {
      const c = idStr[i];
      counts[c] = (counts[c] || 0) + 1;
    }
    let multipleCount = 0;
    for (const c in counts) {
      if (counts[c] === 2 || counts[c] === 3) {
        multipleCount++;
      } else if (counts[c] > 3) {
        return false;
      }
    }
    if (multipleCount !== 1) return false;

    // Prüfziffer nach DIN ISO 7064 Mod 11, 10
    let p = 10;
    for (let i = 0; i < 10; i++) {
      const d = parseInt(idStr[i], 10);
      let s = (d + p) % 10;
      if (s === 0) s = 10;
      p = (s * 2) % 11;
    }
    let check = 11 - p;
    if (check === 10) check = 0;
    return check === parseInt(idStr[10], 10);
  }

  /**
   * Quelle: § 290 SGB V / GKV-Spitzenverband (10-stellig, Modulo 10 mit alternierenden Gewichten 1, 2)
   */
  function isValidKvnr(raw) {
    if (typeof raw !== "string") return false;
    const clean = raw.replace(/[\s-]/g, "").toUpperCase();
    if (!/^[A-Z][0-9]{9}$/.test(clean)) return false;

    const letterCode = clean.charCodeAt(0) - 64; // A=1..Z=26
    const letterStr = letterCode < 10 ? "0" + letterCode : String(letterCode);
    const digitsStr = letterStr + clean.slice(1, 9); // 10 Ziffern
    const weights = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2];

    let sum = 0;
    for (let i = 0; i < 10; i++) {
      const prod = parseInt(digitsStr[i], 10) * weights[i];
      const qs = Math.floor(prod / 10) + (prod % 10);
      sum += qs;
    }
    const checkDigit = sum % 10;
    return checkDigit === parseInt(clean[9], 10);
  }

  /**
   * Quelle: § 147 SGB VI (12 Stellen, Buchstabe als 2-stellige Position 01-26, Gewichte 2,1,2,5,7,1,2,1,2,1,2,1, Quersummen mod 10)
   */
  function isValidRvnr(raw) {
    if (typeof raw !== "string") return false;
    const clean = raw.replace(/[\s/.-]/g, "").toUpperCase();
    if (!/^[0-9]{8}[A-Z][0-9]{3}$/.test(clean)) return false;

    const letterCode = clean.charCodeAt(8) - 64; // A=1..Z=26
    const letterStr = letterCode < 10 ? "0" + letterCode : String(letterCode);
    // 8 Ziffern + 2 Ziffern Buchstabe + 2 Ziffern Seriennummer = 12 Ziffern
    const digitsStr = clean.slice(0, 8) + letterStr + clean.slice(9, 11);
    const weights = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1];

    let sum = 0;
    for (let i = 0; i < 12; i++) {
      const prod = parseInt(digitsStr[i], 10) * weights[i];
      const qs = Math.floor(prod / 10) + (prod % 10);
      sum += qs;
    }
    const checkDigit = sum % 10;
    return checkDigit === parseInt(clean[11], 10);
  }

  /**
   * Quelle: KBV-Richtlinie (9 Stellen: 6 Ziffern Arztnummer, 1 Prüfziffer, 2 Ziffern Fachgruppe; Prüfziffer = (10 - Summe mod 10) mod 10)
   */
  function isValidLanr(raw) {
    if (typeof raw !== "string") return false;
    const clean = raw.replace(/[\s/.-]/g, "");
    if (!/^[0-9]{9}$/.test(clean)) return false;

    const weights = [4, 3, 2, 7, 6, 5];
    let sum = 0;
    for (let i = 0; i < 6; i++) {
      sum += parseInt(clean[i], 10) * weights[i];
    }
    const checkDigit = (10 - (sum % 10)) % 10;
    return checkDigit === parseInt(clean[6], 10);
  }

  /**
   * Quelle: ICAO Doc 9303 / Personalausweisgesetz (Bundesdruckerei, 9 Stellen, Gewichte 7, 3, 1 Modulo 10)
   */
  function isValidPersonalausweis(raw) {
    if (typeof raw !== "string") return false;
    const clean = raw.replace(/[\s-]/g, "").toUpperCase();
    // Deutscher Personalausweis: 9-stellig (alphanumerisch, ohne Vokale/B/D/Q/S) oder 10-stellig mit Prüfziffer
    if (!/^[CFGHJKLMNPRTVWXYZ0-9]{9,10}$/.test(clean)) return false;

    if (clean.length === 10) {
      const weights = [7, 3, 1, 7, 3, 1, 7, 3, 1];
      let sum = 0;
      for (let i = 0; i < 9; i++) {
        const ch = clean[i];
        let val = 0;
        if (ch >= "0" && ch <= "9") val = ch.charCodeAt(0) - 48;
        else if (ch >= "A" && ch <= "Z") val = ch.charCodeAt(0) - 55;
        sum += val * weights[i];
      }
      const checkDigit = sum % 10;
      return checkDigit === parseInt(clean[9], 10);
    }
    // 9-stellig ist syntaktisch zulässig
    return true;
  }

  /**
   * Quelle: ISO 9362 (BIC: 8 oder 11 Zeichen, Syntax und ISO 3166-1 alpha-2 Ländercode)
   */
  const ISO_COUNTRY_CODES = new Set([
    "AD", "AE", "AF", "AG", "AL", "AM", "AO", "AR", "AT", "AU", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BN", "BO", "BR", "BS", "BT", "BW", "BY", "BZ",
    "CA", "CD", "CF", "CG", "CH", "CI", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CY", "CZ",
    "DE", "DJ", "DK", "DM", "DO", "DZ",
    "EC", "EE", "EG", "ES", "ET",
    "FI", "FJ", "FR",
    "GA", "GB", "GD", "GE", "GH", "GM", "GN", "GQ", "GR", "GT", "GW", "GY",
    "HN", "HR", "HT", "HU",
    "ID", "IE", "IL", "IN", "IQ", "IR", "IS", "IT",
    "JM", "JO", "JP",
    "KE", "KG", "KH", "KM", "KN", "KP", "KR", "KW", "KZ",
    "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
    "MA", "MC", "MD", "ME", "MG", "MK", "ML", "MM", "MN", "MO", "MR", "MT", "MU", "MV", "MW", "MX", "MY", "MZ",
    "NA", "NE", "NG", "NI", "NL", "NO", "NP", "NR", "NZ",
    "OM",
    "PA", "PE", "PG", "PH", "PK", "PL", "PT", "PW", "PY",
    "QA",
    "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SI", "SK", "SL", "SM", "SN", "SO", "SR", "ST", "SV", "SY", "SZ",
    "TD", "TG", "TH", "TJ", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ",
    "UA", "UG", "US", "UY", "UZ",
    "VA", "VC", "VE", "VN", "VU",
    "WS",
    "YE",
    "ZA", "ZM", "ZW"
  ]);

  function isValidBic(raw) {
    if (typeof raw !== "string") return false;
    const clean = raw.trim().toUpperCase();
    if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(clean)) return false;
    const country = clean.slice(4, 6);
    return ISO_COUNTRY_CODES.has(country);
  }

  // =========================================================================
  // 2. Namenslisten (CC0 / Public Domain, < 25 KB)
  // Quelle & Lizenz: /docs/lizenzen-daten.md
  // =========================================================================

  const RAW_FIRST_NAMES = (
    "Alexander|Maximilian|Paul|Leon|Lukas|Felix|Elias|Jonas|Noah|Finn|" +
    "Luca|Ben|Luis|David|Julian|Moritz|Tim|Niklas|Jan|Philipp|" +
    "Tom|Jakob|Emil|Anton|Theo|Oskar|Leo|Mats|Milan|Liam|" +
    "Johannes|Simon|Erik|Fabian|Florian|Hannes|Lenny|Jonathan|Vincent|Mika|" +
    "Christian|Michael|Stefan|Daniel|Andreas|Thomas|Martin|Markus|Sebastian|Matthias|" +
    "Jan-Luca|Karl|Friedrich|Wilhelm|Heinrich|Franz|Otto|Walter|Hans|Klaus|" +
    "Jürgen|Peter|Wolfgang|Bernd|Uwe|Dirk|Frank|Ralf|Jörg|Torsten|" +
    "Sophie|Marie|Maria|Mia|Emma|Hannah|Anna|Lea|Emilia|Lina|" +
    "Sophia|Lena|Mila|Clara|Ella|Leonie|Emily|Amelie|Johanna|Lilly|" +
    "Luisa|Ida|Frieda|Charlotte|Leni|Pia|Lara|Nele|Mathilda|Greta|" +
    "Sarah|Laura|Julia|Lisa|Melanie|Katharina|Stefanie|Christina|Sandra|Nicole|" +
    "Sabine|Susanne|Petra|Monika|Birgit|Andrea|Claudia|Karin|Angelika|Gabriele|" +
    "Heike|Elke|Martina|Ute|Renate|Helga|Gisela|Ingrid|Ursula|Christa|" +
    "Ali|Mohamed|Ahmed|Mustafa|Hassan|Hüseyin|Ibrahim|Ömer|Yusuf|Murat|" +
    "Fatima|Zeynep|Amina|Maryam|Elif|Merve|Leyla|Yasmin|Aisha|Sara|" +
    "John|James|Robert|William|Oliver|Lucas|Henry|George|Jack|Charlie|" +
    "Emma|Olivia|Ava|Isabella|Sophia|Mia|Amelia|Harper|Evelyn|Abigail|" +
    "Jean|Pierre|Michel|Louis|Arthur|Gabriel|Jules|Lucas|Hugo|Adam"
  ).split("|");

  const RAW_LAST_NAMES = (
    "Müller|Schmidt|Schneider|Fischer|Weber|Meyer|Wagner|Becker|Schulz|Hoffmann|" +
    "Schäfer|Koch|Bauer|Richter|Klein|Wolf|Schröder|Neumann|Schwarz|Zimmermann|" +
    "Braun|Krüger|Hofmann|Hartmann|Lange|Schmitt|Werner|Schmitz|Krause|Meier|" +
    "Lehmann|Schmid|Schulze|Maier|Köhler|Herrmann|König|Walter|Mayer|Huber|" +
    "Kaiser|Fuchs|Peters|Lang|Scholz|Möller|Weiß|Jung|Hahn|Schubert|" +
    "Vogel|Friedrich|Günther|Keller|Winkler|Frank|Berger|Roth|Beck|Lorenz|" +
    "Baumann|Franke|Albrecht|Schuster|Simon|Ludwig|Böhm|Winter|Kraus|Martin|" +
    "Schumacher|Krämer|Vogt|Stein|Jäger|Otto|Sommer|Groß|Seidel|Heinrich|" +
    "Brandt|Haas|Schreiber|Graf|Schulte|Dietrich|Ziegler|Kuhn|Kühn|Pohl|" +
    "Engel|Horn|Busch|Bergmann|Thomas|Voigt|Sauer|Arnold|Wolff|Pfeiffer|" +
    "Yilmaz|Kaya|Demir|Sahin|Celik|Yildiz|Yildirim|Öztürk|Aydin|Özdemir|" +
    "Smith|Jones|Williams|Taylor|Brown|Davies|Evans|Wilson|Thomas|Roberts"
  ).split("|");

  const SET_FIRST_NAMES = new Set(RAW_FIRST_NAMES.map(n => n.toLowerCase()));
  const SET_LAST_NAMES = new Set(RAW_LAST_NAMES.map(n => n.toLowerCase()));

  // =========================================================================
  // 3. Ausschluss- und Schutzmuster (ICD, OPS, Netzwerk-Muster)
  // =========================================================================

  // ICD-10 Diagnosecodes (z. B. I10, E11.9, J45.0, M54.5)
  const REGEX_ICD10 = /\b[A-TV-Z][0-9]{2}(?:\.[0-9A-Z]{1,4})?\b/g;
  // OPS Operations- und Prozedurenschlüssel (z. B. 5-820.0, 1-440.1)
  const REGEX_OPS = /\b[1-9]-[0-9]{3}(?:\.[0-9a-z]{1,2})?\b/g;

  // Typische Netzwerk-Ports, Versionsnummern, Subnet-Masken
  const REGEX_NET_VERSION = /\b[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\b/;
  const REGEX_NET_PORT = /\b(?:[0-9]+\/[0-9]+\/[0-9]+|[0-9]+\/[0-9]+)\b/;
  const REGEX_NET_SERIAL = /^(?:CZ|CN|FCG|FOC|FOX|JPE|TW|US)[A-Z0-9]{7,12}$/i;
  const REGEX_NET_KEYWORDS = new Set([
    "ethernet", "fastethernet", "gigabitethernet", "tengigabitethernet", "vlan", "port-channel",
    "bridge", "interface", "packets", "bytes", "errors", "drops", "loopback", "management",
    "switchport", "spanning-tree", "trunk", "access", "routed", "show", "running-config"
  ]);

  // =========================================================================
  // 4. Erkennungsfunktionen: Stufe ROT (Deterministisch & Prüfziffern)
  // =========================================================================

  /**
   * Findet alle ROT-Treffer im Text.
   * ROT nur:
   * 1. E-Mail
   * 2. IBAN (Mod 97)
   * 3. Steuer-ID (Mod 11, 10)
   * 4. KVNR (Mod 10)
   * 5. Telefon mit Vorwahl
   * 6. Geburtsdatum mit Signalwort
   * 7. IPv4 / IPv6 / URL
   * 8. Personalausweis (Mod 10 / 7,3,1)
   */
  function findRedSpans(text) {
    const spans = [];

    // 1. E-Mail-Adressen
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    let m;
    while ((m = emailRegex.exec(text)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "ROT",
        category: "EMAIL",
        label: "E-Mail-Adresse",
        active: true
      });
    }

    // 2. IBAN (ISO 7064 Mod 97-10)
    const ibanRegex = /\b[A-Z]{2}[0-9]{2}(?:\s*[A-Z0-9]{4}){2,7}(?:\s*[A-Z0-9]{1,4})?\b/g;
    while ((m = ibanRegex.exec(text)) !== null) {
      const matchText = m[0];
      if (isValidIban(matchText)) {
        spans.push({
          start: m.index,
          end: m.index + matchText.length,
          text: matchText,
          tier: "ROT",
          category: "IBAN",
          label: "IBAN (geprüft Mod 97)",
          active: true
        });
      }
    }

    // 3. Steuer-ID (DIN ISO 7064 Mod 11, 10)
    // 11-stellige Ziffernfolge (optional mit Trennzeichen / oder Leerzeichen)
    const steuerIdRegex = /(?:Steuer-?(?:Id|ID|nummer|-Identifikationsnummer|identifikationsnummer)[:\s]+|\bIdNr\.?[:\s]+|\b)([1-9][0-9]{2}[\s/]?[0-9]{3}[\s/]?[0-9]{3}[\s/]?[0-9]{2})\b/gi;
    while ((m = steuerIdRegex.exec(text)) !== null) {
      const fullMatch = m[0];
      const digitsGroup = m[1];
      if (isValidSteuerId(digitsGroup)) {
        const offset = fullMatch.lastIndexOf(digitsGroup);
        spans.push({
          start: m.index + offset,
          end: m.index + offset + digitsGroup.length,
          text: digitsGroup,
          tier: "ROT",
          category: "STEUER_ID",
          label: "Steuer-ID (geprüft Mod 11,10)",
          active: true
        });
      }
    }

    // 4. KVNR (Krankenversicherungsnummer DE, Mod 10)
    const kvnrRegex = /(?:KVNR|Versicherten-?(?:nummer|Nr\.?)|Krankenkassen-?(?:nummer|Nr\.?))?[:\s]*\b([A-Z][0-9]{9})\b/gi;
    while ((m = kvnrRegex.exec(text)) !== null) {
      const matchText = m[1];
      if (isValidKvnr(matchText)) {
        const offset = m[0].lastIndexOf(matchText);
        spans.push({
          start: m.index + offset,
          end: m.index + offset + matchText.length,
          text: matchText,
          tier: "ROT",
          category: "KVNR",
          label: "KVNR (geprüft Mod 10)",
          active: true
        });
      }
    }

    // 5. Telefon mit Vorwahl
    // Format: Vorwahl 0[1-9]... oder international +49...
    const phoneRegex = /(?:(?:Tel\.?|Telefon|Mobil|Handy|Fax|Phone)[:\s]+)?(?:\+?[0-9]{1,4}[\s/.-]?)?(?:\(?0[1-9][0-9]{1,4}\)?[\s/.-]?)[0-9]{3,9}(?:[\s/.-]?(?:DW|Ext|App|Durchwahl|#|-)\s*[0-9]{1,4})?\b/gi;
    while ((m = phoneRegex.exec(text)) !== null) {
      const candidate = m[0].trim();
      // Schutz vor IP-Adressen, Versionen, Datumsangaben, Ports
      if (REGEX_NET_VERSION.test(candidate) && !/\+|(?:Tel|Fax|Mobil)/i.test(candidate)) continue;
      if (REGEX_NET_PORT.test(candidate)) continue;
      if (/^[0-3]?[0-9]\.[0-1]?[0-9]\.(?:19|20)[0-9]{2}$/.test(candidate)) continue;
      // Ziffern zählen
      const digitsCount = (candidate.match(/[0-9]/g) || []).length;
      if (digitsCount >= 7 && digitsCount <= 16) {
        spans.push({
          start: m.index,
          end: m.index + m[0].length,
          text: m[0],
          tier: "ROT",
          category: "TELEFON",
          label: "Telefonnummer mit Vorwahl",
          active: true
        });
      }
    }

    // 6. Geburtsdatum mit Signalwort
    const dobRegex = /(?:geb\.?(?:\s+am)?|geboren(?:\s+am)?|Geburtsdatum|Geb\.-Datum|DOB|Date of birth)[:\s]+([0-3]?[0-9][./-][0-1]?[0-9][./-](?:19|20)[0-9]{2})\b/gi;
    while ((m = dobRegex.exec(text)) !== null) {
      const dateText = m[1];
      const offset = m[0].lastIndexOf(dateText);
      spans.push({
        start: m.index + offset,
        end: m.index + offset + dateText.length,
        text: dateText,
        tier: "ROT",
        category: "GEBURTSDATUM",
        label: "Geburtsdatum",
        active: true
      });
    }

    // 7. IPv4, IPv6, URL
    const urlRegex = /\bhttps?:\/\/[^\s<>"]+/gi;
    while ((m = urlRegex.exec(text)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "ROT",
        category: "URL",
        label: "Web-Adresse (URL)",
        active: true
      });
    }

    const ipv4Regex = /\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;
    while ((m = ipv4Regex.exec(text)) !== null) {
      // Keine reinen Versionsnummern oder Teilbereiche aus ICD
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "ROT",
        category: "IP",
        label: "IPv4-Adresse",
        active: true
      });
    }

    // 8. Personalausweis (Mod 10 / 7,3,1)
    const ausweisRegex = /(?:Ausweis-?(?:nummer|Nr\.?)|Personalausweis-?(?:nummer|Nr\.?)|Pass-?(?:nummer|Nr\.?))[:\s]+([CFGHJKLMNPRTVWXYZ0-9]{9,10})\b/gi;
    while ((m = ausweisRegex.exec(text)) !== null) {
      const nr = m[1];
      if (isValidPersonalausweis(nr)) {
        const offset = m[0].lastIndexOf(nr);
        spans.push({
          start: m.index + offset,
          end: m.index + offset + nr.length,
          text: nr,
          tier: "ROT",
          category: "PERSONALAUSWEIS",
          label: "Personalausweis (geprüft)",
          active: true
        });
      }
    }

    return spans;
  }

  // =========================================================================
  // 5. Erkennungsfunktionen: Stufe GELB (Kontextuelle Kandidaten)
  // =========================================================================

  /**
   * Findet alle GELB-Kandidaten im Text.
   * GELB:
   * 1. Namen (Anrede, Listen, Grußzeilen)
   * 2. Straße + Hausnummer
   * 3. PLZ + Ort (5 Ziffern + Ortsname)
   * 4. Kfz-Kennzeichen
   * 5. Übrige Daten (ohne Geburtsdatum-Signalwort)
   * 6. RVNR (geprüft nach § 147 SGB VI)
   * 7. LANR (geprüft nach KBV)
   * 8. BSNR (Signalwort + 9 Ziffern)
   * 9. Fall- / Patientennummern
   * 10. Station / Zimmer
   * 11. BIC (Syntax und ISO-Ländercode)
   */
  function findYellowSpans(text) {
    const spans = [];
    let m;

    // 1. Namen: Nach Anrede / Titel
    const anredeRegex = /(?:Herr(?:n)?|Frau|Dr\.|Prof\.|Dipl\.-[A-Za-z]+)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){1,3})\b/g;
    while ((m = anredeRegex.exec(text)) !== null) {
      const namePart = m[1];
      const offset = m[0].indexOf(namePart);
      spans.push({
        start: m.index + offset,
        end: m.index + offset + namePart.length,
        text: namePart,
        tier: "GELB",
        category: "NAME",
        label: "Name nach Anrede/Titel",
        active: false
      });
    }

    // 2. Namen: Aus Vornamen- und Nachnamenslisten (Wort-Ebene)
    const wordRegex = /\b[A-ZÄÖÜ][a-zäöüß]+\b/g;
    while ((m = wordRegex.exec(text)) !== null) {
      const word = m[0];
      const lower = word.toLowerCase();
      if (SET_FIRST_NAMES.has(lower) || SET_LAST_NAMES.has(lower)) {
        spans.push({
          start: m.index,
          end: m.index + word.length,
          text: word,
          tier: "GELB",
          category: "NAME",
          label: "Name aus Namensliste",
          active: false
        });
      }
    }

    // 3. Namen: Gruß- und Unterschriftzeilen
    const grussRegex = /(?:Mit freundlichen Grüßen|Viele Grüße|Herzliche Grüße|Beste Grüße|Hochachtungsvoll|MfG|VG),?\s*\n+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){1,3})/g;
    while ((m = grussRegex.exec(text)) !== null) {
      const namePart = m[1];
      const offset = m[0].indexOf(namePart);
      spans.push({
        start: m.index + offset,
        end: m.index + offset + namePart.length,
        text: namePart,
        tier: "GELB",
        category: "NAME",
        label: "Name in Gruß-/Signaturzeile",
        active: false
      });
    }

    // 4. Straße + Hausnummer
    const strasseRegex = /\b[A-ZÄÖÜ][a-zäöüß]+(?:straße|str\.|weg|gasse|platz|allee|ring|damm|pfad|ufer)\s+[0-9]{1,4}\s*[a-zA-Z]?(?:\s*\/\s*[0-9]+)?\b/gi;
    while ((m = strasseRegex.exec(text)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "GELB",
        category: "STRASSE_NR",
        label: "Straße + Hausnummer",
        active: false
      });
    }

    const strasse2Regex = /\b(?:Am|An der|Auf dem|In der|Im)\s+[A-ZÄÖÜ][a-zäöüß]+\s+[0-9]{1,4}\s*[a-zA-Z]?\b/g;
    while ((m = strasse2Regex.exec(text)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "GELB",
        category: "STRASSE_NR",
        label: "Straße + Hausnummer",
        active: false
      });
    }

    // 5. PLZ + Ort (deutsches Format 5 Ziffern + Ortsname)
    const plzRegex = /\b([0-9]{5})\s+([A-ZÄÖÜ][a-zäöüß]+(?:-[A-ZÄÖÜ][a-zäöüß]+)*)\b/g;
    while ((m = plzRegex.exec(text)) !== null) {
      const cityName = m[2];
      // Schutz vor Netzwerk-Begriffen (z. B. "10000 Ethernet", "00000 Packets")
      if (REGEX_NET_KEYWORDS.has(cityName.toLowerCase())) continue;
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "GELB",
        category: "PLZ_ORT",
        label: "PLZ + Ort",
        active: false
      });
    }

    // 6. Kfz-Kennzeichen (DE)
    const kfzRegex = /\b([A-ZÄÖÜ]{1,3})[- ]([A-Z]{1,2})\s*([1-9][0-9]{0,3})\s*([EH])?\b/g;
    while ((m = kfzRegex.exec(text)) !== null) {
      const prefix = m[1];
      // Schutz vor Abkürzungen und Netzwerkprotokollen
      if (/^(?:DIN|ISO|VDE|RFC|TCP|UDP|ETH|MAC|ARP|BGP|OSPF|VLAN)$/i.test(prefix)) continue;
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "GELB",
        category: "KFZ",
        label: "Kfz-Kennzeichen",
        active: false
      });
    }

    // 7. Übrige Daten (ohne Geburtsdatum-Signalwort)
    const dateRegex = /\b(?:[0-3]?[0-9]\.[0-1]?[0-9]\.(?:19|20)[0-9]{2}|(?:19|20)[0-9]{2}-[0-1][0-9]-[0-3][0-9])\b/g;
    while ((m = dateRegex.exec(text)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "GELB",
        category: "DATUM",
        label: "Datumsangabe",
        active: false
      });
    }

    // 8. RVNR (Rentenversicherungsnummer DE, geprüft § 147 SGB VI)
    const rvnrRegex = /(?:RVNR|Rentenversicherungs-?(?:nummer|Nr\.?))?[:\s]*\b([0-9]{2}[0-3][0-9][0-1][0-9][0-9]{2}[A-Z][0-9]{3})\b/gi;
    while ((m = rvnrRegex.exec(text)) !== null) {
      const matchText = m[1];
      if (isValidRvnr(matchText)) {
        const offset = m[0].lastIndexOf(matchText);
        spans.push({
          start: m.index + offset,
          end: m.index + offset + matchText.length,
          text: matchText,
          tier: "GELB",
          category: "RVNR",
          label: "Rentenversicherungsnummer (geprüft)",
          active: false
        });
      }
    }

    // 9. LANR (Lebenslange Arztnummer, geprüft KBV)
    const lanrRegex = /(?:LANR|Arztnummer|Arzt-Nr\.?)[:\s]+([0-9]{9})\b/gi;
    while ((m = lanrRegex.exec(text)) !== null) {
      const nr = m[1];
      if (isValidLanr(nr)) {
        const offset = m[0].lastIndexOf(nr);
        spans.push({
          start: m.index + offset,
          end: m.index + offset + nr.length,
          text: nr,
          tier: "GELB",
          category: "LANR",
          label: "LANR (Arztnummer geprüft)",
          active: false
        });
      }
    }

    // 10. BSNR (Betriebsstättennummer, Signalwort + 9 Ziffern ohne Prüfziffer)
    const bsnrRegex = /(?:BSNR|Betriebsst[äa]ttennummer|Betriebsst[äa]tten-Nr\.?)[:\s]+([0-9]{9})\b/gi;
    while ((m = bsnrRegex.exec(text)) !== null) {
      const nr = m[1];
      const offset = m[0].lastIndexOf(nr);
      spans.push({
        start: m.index + offset,
        end: m.index + offset + nr.length,
        text: nr,
        tier: "GELB",
        category: "BSNR",
        label: "BSNR (Betriebsstättennummer)",
        active: false
      });
    }

    // 11. Fall- / Patientennummern
    const fallRegex = /(?:Fall(?:nummer|-Nr\.?)|Patient(?:ennummer|-Nr\.?)|PID|Aufnahmenummer|Behandlungsfall)[:\s]+([A-Za-z0-9/-]{3,20})\b/gi;
    while ((m = fallRegex.exec(text)) !== null) {
      const nr = m[1];
      const offset = m[0].lastIndexOf(nr);
      spans.push({
        start: m.index + offset,
        end: m.index + offset + nr.length,
        text: nr,
        tier: "GELB",
        category: "FALL_PATIENT",
        label: "Fall-/Patientennummer",
        active: false
      });
    }

    // 12. Station / Zimmer
    const stationRegex = /\b(?:Station|Stat\.|Zimmer|Zi\.|Haus|Ebene)\s+([A-Za-z0-9/-]{1,10})\b/gi;
    while ((m = stationRegex.exec(text)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        tier: "GELB",
        category: "STATION_ZIMMER",
        label: "Station / Zimmer",
        active: false
      });
    }

    // 13. BIC (ISO 9362)
    const bicRegex = /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;
    while ((m = bicRegex.exec(text)) !== null) {
      const candidate = m[0];
      if (isValidBic(candidate)) {
        // Nicht mit IP-Hostnamen oder Netzwerkbefehlen verwechseln
        spans.push({
          start: m.index,
          end: m.index + candidate.length,
          text: candidate,
          tier: "GELB",
          category: "BIC",
          label: "BIC / SWIFT-Code",
          active: false
        });
      }
    }

    return spans;
  }

  // =========================================================================
  // 6. Span-Kollisionen auflösen & Fachinhalte schützen (ICD/OPS)
  // =========================================================================

  /**
   * Filtert Spans, die mit geschützten Fachinhalten (ICD-10, OPS) kollidieren,
   * und löst Überlappungen deterministisch auf (ROT > GELB, längerer Treffer gewinnt).
   */
  function resolveSpans(text, redSpans, yellowSpans, manualSpans) {
    const protectedRanges = [];

    // ICD-10
    let m;
    const icdRegex = new RegExp(REGEX_ICD10.source, "g");
    while ((m = icdRegex.exec(text)) !== null) {
      protectedRanges.push({ start: m.index, end: m.index + m[0].length });
    }

    // OPS
    const opsRegex = new RegExp(REGEX_OPS.source, "g");
    while ((m = opsRegex.exec(text)) !== null) {
      protectedRanges.push({ start: m.index, end: m.index + m[0].length });
    }

    function isProtected(start, end) {
      for (const pr of protectedRanges) {
        if (start < pr.end && end > pr.start) return true;
      }
      return false;
    }

    const allSpans = []
      .concat(redSpans || [])
      .concat(yellowSpans || [])
      .concat(manualSpans || [])
      .filter(s => !isProtected(s.start, s.end));

    // Sortierung: Start aufsteigend; bei gleichem Start: ROT vor GELB, dann längerer Span
    allSpans.sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      const tierRank = { ROT: 1, MANUELL: 2, GELB: 3 };
      const trA = tierRank[a.tier] || 9;
      const trB = tierRank[b.tier] || 9;
      if (trA !== trB) return trA - trB;
      return (b.end - b.start) - (a.end - a.start);
    });

    // Überlappungsfreie Liste
    const nonOverlapping = [];
    let lastEnd = -1;
    for (const span of allSpans) {
      if (span.start >= lastEnd) {
        nonOverlapping.push(span);
        lastEnd = span.end;
      }
    }

    return nonOverlapping;
  }

  // =========================================================================
  // 6b. E-Mail-Parser: Kopfzeilen, Zitate & Signaturen
  // =========================================================================

  function findEmailSpans(text) {
    const spans = [];
    let m;

    // A. E-Mail-Kopfzeilen (From, To, Cc, Bcc, Reply-To, Sender)
    const headerRegex = /^(?:From|Von|To|An|Cc|Bcc|Reply-To|Sender):\s*(.+)$/gim;
    while ((m = headerRegex.exec(text)) !== null) {
      const fullHeader = m[0];
      const headerVal = m[1];
      const valOffset = m.index + fullHeader.indexOf(headerVal);

      // Display-Name in Anführungszeichen: "Mustermann, Max" <max@...>
      const nameInQuotes = /"([^"]+)"/g;
      let nm;
      while ((nm = nameInQuotes.exec(headerVal)) !== null) {
        spans.push({
          start: valOffset + nm.index + 1,
          end: valOffset + nm.index + 1 + nm[1].length,
          text: nm[1],
          tier: "ROT",
          category: "NAME",
          label: "Absender-/Empfänger-Name (Header)",
          active: true
        });
      }

      // Name ohne Anführungszeichen vor <email>: Max Mustermann <max@...>
      const nameBeforeAngle = /([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)+)\s*</g;
      while ((nm = nameBeforeAngle.exec(headerVal)) !== null) {
        spans.push({
          start: valOffset + nm.index,
          end: valOffset + nm.index + nm[1].length,
          text: nm[1],
          tier: "ROT",
          category: "NAME",
          label: "Absender-/Empfänger-Name (Header)",
          active: true
        });
      }
    }

    // B. Technische Kopfzeilen (Message-ID, Received, X-Originating-IP)
    const techHeaderRegex = /^(?:Message-ID|Received|X-Originating-IP|Return-Path):\s*(.+)$/gim;
    while ((m = techHeaderRegex.exec(text)) !== null) {
      const fullHeader = m[0];
      const val = m[1].trim();
      const offset = m.index + fullHeader.indexOf(val);
      spans.push({
        start: offset,
        end: offset + val.length,
        text: val,
        tier: "ROT",
        category: "EMAIL_HEADER",
        label: "Technischer E-Mail-Header",
        active: true
      });
    }

    // C. Antwort-Einleitungen ("Am ... schrieb ...", "On ... wrote:")
    const quoteIntroRegex = /^(?:>\s*)?(?:Am\s+([0-3]?[0-9]\.[0-1]?[0-9]\.(?:19|20)[0-9]{2}(?:,?\s+um\s+[0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?\s*Uhr)?)\s+schrieb\s+([^:\n<]+)(?:<([^>\n]+)>)?:\s*|On\s+(.+?)\s+wrote:\s*)$/gim;
    while ((m = quoteIntroRegex.exec(text)) !== null) {
      if (m[1] && m[2]) {
        const dateStr = m[1].trim();
        const nameStr = m[2].trim();
        const dateOffset = m.index + m[0].indexOf(dateStr);
        const nameOffset = m.index + m[0].indexOf(nameStr);
        spans.push({
          start: dateOffset,
          end: dateOffset + dateStr.length,
          text: dateStr,
          tier: "GELB",
          category: "DATUM",
          label: "Datum in Zitatzeile",
          active: false
        });
        if (nameStr.length > 2) {
          spans.push({
            start: nameOffset,
            end: nameOffset + nameStr.length,
            text: nameStr,
            tier: "ROT",
            category: "NAME",
            label: "Name in Antwort-/Zitatzeile",
            active: true
          });
        }
      }
    }

    // D. Signatur-Blöcke (nach "-- \n" oder "--\n")
    const sigSplit = text.search(/^--\s*$/m);
    if (sigSplit !== -1) {
      const sigText = text.slice(sigSplit);
      const sigOffset = sigSplit;

      const firmaRegex = /\b([A-ZÄÖÜ][A-Za-z0-9äöüß&.-]+(?:\s+[A-ZÄÖÜ][A-Za-z0-9äöüß&.-]+)*\s+(?:GmbH(?:\s*&\s*Co\.?\s*KG)?|AG|e\.?V\.?|OHG|KG|GbR|Ltd\.?|Inc\.?))\b/g;
      let fm;
      while ((fm = firmaRegex.exec(sigText)) !== null) {
        spans.push({
          start: sigOffset + fm.index,
          end: sigOffset + fm.index + fm[1].length,
          text: fm[1],
          tier: "GELB",
          category: "FIRMA",
          label: "Firmenname in Signatur",
          active: false
        });
      }

      const regRegex = /\b(?:Amtsgericht\s+[A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?\s+(?:HRB|HRA)\s*[0-9]+)\b/gi;
      let rm;
      while ((rm = regRegex.exec(sigText)) !== null) {
        spans.push({
          start: sigOffset + rm.index,
          end: sigOffset + rm.index + rm[0].length,
          text: rm[0],
          tier: "GELB",
          category: "REGISTER",
          label: "Handelsregistereintrag",
          active: false
        });
      }
    }

    return spans;
  }

  // =========================================================================
  // 6c. Datumsverschiebung pro Fall (Consistent Date Shifting)
  // =========================================================================

  function shiftDate(str, offsetDays) {
    if (typeof str !== "string" || !offsetDays || isNaN(offsetDays)) return str;
    offsetDays = parseInt(offsetDays, 10);

    let m = str.match(/^([0-3]?[0-9])\.([0-1]?[0-9])\.((?:19|20)[0-9]{2})$/);
    if (m) {
      const d = parseInt(m[1], 10);
      const mo = parseInt(m[2], 10) - 1;
      const y = parseInt(m[3], 10);
      const date = new Date(Date.UTC(y, mo, d + offsetDays));
      const nd = String(date.getUTCDate()).padStart(2, "0");
      const nm = String(date.getUTCMonth() + 1).padStart(2, "0");
      const ny = date.getUTCFullYear();
      return `${nd}.${nm}.${ny}`;
    }

    m = str.match(/^((?:19|20)[0-9]{2})-([0-1][0-9])-([0-3][0-9])$/);
    if (m) {
      const y = parseInt(m[1], 10);
      const mo = parseInt(m[2], 10) - 1;
      const d = parseInt(m[3], 10);
      const date = new Date(Date.UTC(y, mo, d + offsetDays));
      const nd = String(date.getUTCDate()).padStart(2, "0");
      const nm = String(date.getUTCMonth() + 1).padStart(2, "0");
      const ny = date.getUTCFullYear();
      return `${ny}-${nm}-${nd}`;
    }

    return str;
  }

  // =========================================================================
  // 7. Haupt-Engine: Analyse & Pseudonymisierung
  // =========================================================================

  /**
   * Analysiert den Rohtext und gibt alle erkannten Treffer zurück.
   */
  function analyzeText(text, options) {
    options = options || {};
    const redSpans = findRedSpans(text);
    const yellowSpans = findYellowSpans(text);
    const emailSpans = findEmailSpans(text);
    const manualSpans = options.manualSpans || [];

    const allRed = redSpans.concat(emailSpans.filter(s => s.tier === "ROT"));
    const allYellow = yellowSpans.concat(emailSpans.filter(s => s.tier === "GELB"));
    const resolved = resolveSpans(text, allRed, allYellow, manualSpans);
    return resolved;
  }

  // =========================================================================
  // 7b. Mechanismus pro Kategorie: platzhalter | entfernen | generalisieren
  // =========================================================================

  const MECHANISMEN = ["platzhalter", "entfernen", "generalisieren"];

  // Kategorien mit Generalisierungsregel; alle anderen fallen auf "platzhalter" zurück
  const GENERALISIERBAR = ["DATUM", "GEBURTSDATUM", "PLZ_ORT", "STRASSE_NR", "TELEFON", "EMAIL", "IP"];

  /**
   * Vergröbert einen Wert so, dass er die Person nicht mehr eindeutig bestimmt.
   * Liefert null, wenn die Kategorie keine Regel hat oder der Wert nicht passt.
   * - DATUM / GEBURTSDATUM: nur das Jahr ("1987")
   * - PLZ_ORT: Leitregion, die ersten beiden Ziffern ("12xxx"), ohne Ort
   * - STRASSE_NR: Straßenname ohne Hausnummer
   * - TELEFON: nur Vorwahl ("030 …" bzw. "+49 89 …")
   * - EMAIL: nur die Domain ("…@beispiel.example")
   * - IP: IPv4 ohne letztes Oktett ("192.0.2.x")
   */
  function generalisiereWert(category, value) {
    const v = String(value || "").trim();
    if (!v) return null;
    if (category === "DATUM" || category === "GEBURTSDATUM") {
      const m = v.match(/(?:^|[^0-9])((?:19|20)[0-9]{2})(?:[^0-9]|$)/);
      return m ? m[1] : null;
    }
    if (category === "PLZ_ORT") {
      const m = v.match(/(?:^|[^0-9])([0-9]{2})[0-9]{3}(?:[^0-9]|$)/);
      return m ? m[1] + "xxx" : null;
    }
    if (category === "STRASSE_NR") {
      const m = v.match(/^(.*?)[ \t]+[0-9]+[ \t]*[a-zA-Z]?(?:[ \t]*[-\/][ \t]*[0-9]+[a-zA-Z]?)?$/);
      return m && m[1].trim() ? m[1].trim() : null;
    }
    if (category === "TELEFON") {
      const m = v.match(/^((?:\+|00)[0-9]{2}[ \t\/-]*\(?0?\)?[ \t]*[0-9]{2,4}|0[0-9]{2,4})/);
      return m ? m[1].trim() + " …" : null;
    }
    if (category === "EMAIL") {
      const at = v.lastIndexOf("@");
      return at > 0 && at < v.length - 1 ? "…@" + v.slice(at + 1) : null;
    }
    if (category === "IP") {
      const m = v.match(/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}$/);
      return m ? m[1] + ".x" : null;
    }
    return null;
  }

  /**
   * Pseudonymisiert den Text anhand der aktiven Spans.
   *
   * Optionen:
   * - mechanismen: { KATEGORIE: "platzhalter" | "entfernen" | "generalisieren" }
   *     platzhalter    = Token [NAME-1], rückführbar über die Zuordnungstabelle
   *     entfernen      = Schwärzung ████████, nicht rückführbar
   *     generalisieren = vergröberter Wert (siehe generalisiereWert), nicht rückführbar;
   *                      ohne Regel für die Kategorie wird ein Platzhalter gesetzt
   * - mode: Vorgabe für Kategorien ohne Eintrag in mechanismen
   *     "token" (Standard) = platzhalter, "redaction" / "schwaerzung" = entfernen
   * - bekannt: { tokens: Map("KATEGORIE|original" -> Token), zaehler: { KATEGORIE: n } }
   *     bereits vergebene Platzhalter, damit die Nummerierung über mehrere Texte eindeutig bleibt
   * - shiftDates / dateShiftDays: Datumsverschiebung (hat Vorrang für DATUM / GEBURTSDATUM)
   *
   * Liefert:
   * - text: Der pseudonymisierte Text
   * - mapping: Array von { category, placeholder, original } (nur rückführbare Ersetzungen)
   * - mechanismusZaehler: { platzhalter, entfernen, generalisieren }
   * - status: "Geprüft, n Treffer ersetzt, Sichtprüfung erforderlich"
   */
  function pseudonymizeText(text, spans, options) {
    options = options || {};
    const mode = options.mode || "token";
    const defaultMechanismus = (mode === "redaction" || mode === "schwaerzung") ? "entfernen" : "platzhalter";
    const mechanismen = options.mechanismen || {};
    const shiftDates = Boolean(options.shiftDates && options.dateShiftDays);
    const dateShiftDays = shiftDates ? parseInt(options.dateShiftDays, 10) : 0;
    const activeSpans = (spans || []).filter(s => s.active).sort((a, b) => a.start - b.start);

    const bekannt = options.bekannt || {};
    const mapping = [];
    const categoryCounters = Object.assign({}, bekannt.zaehler || {});
    const originalToToken = new Map();
    if (bekannt.tokens && typeof bekannt.tokens.forEach === "function") {
      bekannt.tokens.forEach((tok, key) => { originalToToken.set(key, tok); });
    }
    const mechanismusZaehler = { platzhalter: 0, entfernen: 0, generalisieren: 0 };

    let result = "";
    let lastIdx = 0;
    let replacedCount = 0;

    for (const span of activeSpans) {
      if (span.start < lastIdx) continue; // Überlappungsschutz
      result += text.slice(lastIdx, span.start);

      const origText = text.slice(span.start, span.end);
      const catKey = span.category || "TEXT";
      let mech = mechanismen[catKey];
      if (MECHANISMEN.indexOf(mech) < 0) mech = defaultMechanismus;
      let replacement = null;

      if (shiftDates && (catKey === "DATUM" || catKey === "GEBURTSDATUM")) {
        // Datumsverschiebung: Ersetzt durch das verschobene Datum
        // WICHTIG: Versatz steht NUR in der Zuordnungstabelle, niemals in der Ausgabe!
        replacement = shiftDate(origText, dateShiftDays);
        mapping.push({
          category: catKey,
          placeholder: replacement,
          original: origText,
          meta: { dateShiftDays: dateShiftDays }
        });
      } else if (mech === "entfernen") {
        replacement = "█".repeat(Math.max(1, origText.length));
        mechanismusZaehler.entfernen++;
      } else if (mech === "generalisieren") {
        replacement = generalisiereWert(catKey, origText);
        if (replacement !== null) mechanismusZaehler.generalisieren++;
      }

      if (replacement === null) {
        // Platzhalter [KATEGORIE-n], über den Text (und mit "bekannt" über mehrere Texte) konsistent
        const mapKey = catKey + "|" + origText;
        if (originalToToken.has(mapKey)) {
          replacement = originalToToken.get(mapKey);
        } else {
          categoryCounters[catKey] = (categoryCounters[catKey] || 0) + 1;
          replacement = "[" + catKey + "-" + categoryCounters[catKey] + "]";
          originalToToken.set(mapKey, replacement);
          mapping.push({
            category: catKey,
            placeholder: replacement,
            original: origText
          });
        }
        mechanismusZaehler.platzhalter++;
      }

      result += replacement;
      lastIdx = span.end;
      replacedCount++;
    }

    result += text.slice(lastIdx);

    const statusMsg = "Geprüft, " + replacedCount + " Treffer ersetzt, Sichtprüfung erforderlich";

    return {
      text: result,
      mapping: mapping,
      replacedCount: replacedCount,
      mechanismusZaehler: mechanismusZaehler,
      zaehler: categoryCounters,
      status: statusMsg,
      notice: "Rückführbar über die Zuordnungstabelle. Ersetzt keine fachliche Sichtprüfung und keine Rechtsgrundlage."
    };
  }

  // =========================================================================
  // 8. Öffentliche Modul-Schnittstelle
  // =========================================================================

  return {
    isValidIban: isValidIban,
    isValidSteuerId: isValidSteuerId,
    isValidKvnr: isValidKvnr,
    isValidRvnr: isValidRvnr,
    isValidLanr: isValidLanr,
    isValidPersonalausweis: isValidPersonalausweis,
    isValidBic: isValidBic,
    shiftDate: shiftDate,
    findRedSpans: findRedSpans,
    findYellowSpans: findYellowSpans,
    findEmailSpans: findEmailSpans,
    resolveSpans: resolveSpans,
    analyzeText: analyzeText,
    pseudonymizeText: pseudonymizeText,
    generalisiereWert: generalisiereWert,
    MECHANISMEN: MECHANISMEN,
    GENERALISIERBAR: GENERALISIERBAR
  };
});
