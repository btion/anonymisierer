  // core/tabelle/zuordnung.js
  // Zuordnungstabelle (AnonState), Rückübersetzung und Text-Platzhalter [KATEGORIE-n].
  // Gemeinsamer Kern für web/anonymisierer.html und web/text/text-anonymisierer.html.
  // Wird mit "node tools/einbetten.js" in beide Seiten eingebettet; die Tests prüfen die Gleichheit.

  function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  class AnonState {
    constructor() {
      this.forward = new Map();      // lowerKey -> token
      this.reverse = new Map();      // UPPER_TOKEN -> originalValue
      this.reverseKeys = new Map();  // UPPER_TOKEN -> canonicalToken
      this.counters = new Map();     // UPPER_PREFIX -> int
      this.netHostForward = new Map(); // UPPER_NET_TOKEN -> Map(hostOctet -> Hn)
      this.stats = new Map();        // category -> count
      this.aliases = new Map();      // UPPER_OLD_TOKEN -> neuer Platzhalter oder "__REMOVED__" (nur für Rückübersetzung)
    }

    nextCounter(prefix) {
      const k = prefix.toUpperCase();
      const val = (this.counters.get(k) || 0) + 1;
      this.counters.set(k, val);
      return val;
    }

    addStat(category, count = 1) {
      if (count <= 0) return;
      this.stats.set(category, (this.stats.get(category) || 0) + count);
    }

    getOrCreateToken(categoryKey, rawValue, prefix, reverseDisplayVal) {
      const trimmed = rawValue.trim();
      const lookupKey = (categoryKey + "|" + trimmed).toLowerCase();
      if (this.forward.has(lookupKey)) {
        return this.forward.get(lookupKey);
      }
      // Zentrale Vergabe: nie einen Platzhalter, der schon vergeben, fest zugeordnet oder als Alias reserviert ist
      let token;
      do {
        token = prefix + "-" + this.nextCounter(prefix);
      } while (this.reverse.has(token.toUpperCase()) || this.aliases.has(token.toUpperCase()));
      this.forward.set(lookupKey, token);
      const revKey = token.toUpperCase();
      if (!this.reverse.has(revKey)) {
        this.reverse.set(revKey, reverseDisplayVal ? reverseDisplayVal.trim() : trimmed);
        this.reverseKeys.set(revKey, token);
      }
      return token;
    }

    registerFixed(rawValue, token) {
      const lookupKey = ("FIXED|" + rawValue.trim()).toLowerCase();
      this.forward.set(lookupKey, token);
      const revKey = token.toUpperCase();
      if (!this.reverse.has(revKey)) {
        this.reverse.set(revKey, rawValue);
        this.reverseKeys.set(revKey, token);
      }
    }

    toJSON() {
      const vorwaerts = {};
      Array.from(this.forward.keys()).sort().forEach(k => { vorwaerts[k] = this.forward.get(k); });
      const rueckwaerts = {};
      Array.from(this.reverseKeys.keys()).sort().forEach(rk => {
        const canon = this.reverseKeys.get(rk);
        rueckwaerts[canon] = this.reverse.get(rk);
      });
      const zaehler = {};
      Array.from(this.counters.keys()).sort().forEach(k => { zaehler[k] = this.counters.get(k); });
      const netzHosts = {};
      Array.from(this.netHostForward.keys()).sort().forEach(nk => {
        const sub = {};
        const m = this.netHostForward.get(nk);
        Array.from(m.keys()).sort().forEach(hk => { sub[hk] = m.get(hk); });
        netzHosts[nk] = sub;
      });
      const aliase = {};
      Array.from(this.aliases.keys()).sort().forEach(ak => { aliase[ak] = this.aliases.get(ak); });
      return {
        version: "1.0",
        erstelltAm: new Date().toISOString(),
        vorwaerts,
        rueckwaerts,
        zaehler,
        netzHosts,
        aliase
      };
    }

    static fromJSON(obj) {
      const st = new AnonState();
      if (!obj) return st;
      if (obj.vorwaerts) {
        for (const [k, v] of Object.entries(obj.vorwaerts)) {
          st.forward.set(k.toLowerCase(), String(v));
        }
      }
      if (obj.rueckwaerts) {
        for (const [k, v] of Object.entries(obj.rueckwaerts)) {
          st.reverse.set(k.toUpperCase(), String(v));
          st.reverseKeys.set(k.toUpperCase(), k);
        }
      }
      if (obj.zaehler) {
        for (const [k, v] of Object.entries(obj.zaehler)) {
          st.counters.set(k.toUpperCase(), Number(v));
        }
      }
      if (obj.netzHosts) {
        for (const [nk, sub] of Object.entries(obj.netzHosts)) {
          const m = new Map();
          for (const [hk, hv] of Object.entries(sub)) {
            m.set(String(hk), String(hv));
          }
          st.netHostForward.set(nk.toUpperCase(), m);
        }
      }
      if (obj.aliase) {
        for (const [ak, av] of Object.entries(obj.aliase)) {
          st.aliases.set(ak.toUpperCase(), String(av));
        }
      }
      return st;
    }
  }

  // Eindeutigkeit der Platzhalter: ein Platzhalter darf nur für einen Originalwert stehen
  // (identisch zu AnonEngine.FindPlaceholderCollisions in anon.ps1; Meldungen enthalten keine Originalwerte)
  function findPlaceholderCollisions(state, festeZuordnung) {
    const byToken = new Map();
    const add = (tok, raw) => {
      if (!tok) return;
      const k = String(tok).toUpperCase();
      if (!byToken.has(k)) byToken.set(k, new Set());
      byToken.get(k).add(String(raw == null ? "" : raw).trim().toLowerCase());
    };
    for (const [key, tok] of state.forward.entries()) {
      const bar = key.indexOf("|");
      add(tok, bar >= 0 ? key.slice(bar + 1) : key);
    }
    for (const [orig, ph] of Object.entries(festeZuordnung || {})) {
      if (!String(orig).trim() || !String(ph || "").trim()) continue;
      const p = String(ph).trim();
      add(p, orig);
      if (state.reverse.has(p.toUpperCase())) add(p, state.reverse.get(p.toUpperCase()));
    }
    const result = [];
    for (const tok of Array.from(byToken.keys()).sort()) {
      const n = byToken.get(tok).size;
      if (n > 1) result.push(`Platzhalter ${tok} steht für ${n} verschiedene Originalwerte`);
    }
    return result;
  }

  function deanonymizeText(input, state) {
    if (!input || !state || !state.reverse || state.reverse.size === 0) return input;
    const sortedUpperKeys = Array.from(state.reverse.keys()).filter(Boolean).sort((a, b) => b.length - a.length);
    if (sortedUpperKeys.length === 0) return input;
    const escapedTokens = sortedUpperKeys.map(k => escapeRegExp(k));
    const combinedRx = new RegExp(`(?<![A-Za-z0-9])(?:${escapedTokens.join("|")})(?![0-9])`, "gi");
    return input.replace(combinedRx, (m) => {
      const orig = state.reverse.get(m.toUpperCase());
      return orig !== undefined ? orig : m;
    });
  }

  // Text-Reiter: Platzhalter [KATEGORIE-n] aus der Zuordnungstabelle lesen bzw. dort eintragen,
  // damit die Nummerierung über mehrere Texte eindeutig bleibt
  function collectKnownTextTokens(state) {
    const tokens = new Map();
    const zaehler = {};
    for (const [upper, canon] of state.reverseKeys.entries()) {
      const m = /^\[([A-Z_]+)-([0-9]+)\]$/.exec(canon);
      if (!m) continue;
      tokens.set(m[1] + "|" + state.reverse.get(upper), canon);
      zaehler[m[1]] = Math.max(zaehler[m[1]] || 0, parseInt(m[2], 10));
    }
    return { tokens, zaehler };
  }

  function registerTextMappingInState(state, mapping) {
    for (const item of mapping) {
      if (!item || !item.placeholder || item.meta) continue; // verschobene Daten sind kein Platzhalter
      const upper = item.placeholder.toUpperCase();
      state.forward.set(("TEXT_" + item.category + "|" + item.original).toLowerCase(), item.placeholder);
      if (!state.reverse.has(upper)) {
        state.reverse.set(upper, item.original);
        state.reverseKeys.set(upper, item.placeholder);
      }
    }
  }
