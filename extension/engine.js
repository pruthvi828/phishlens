/*
 * PhishLens Student Shield — client-side phishing risk analysis engine.
 * Pure JavaScript, zero dependencies, zero network calls.
 * Runs identically inside the browser extension (content script / popup)
 * and the web demo page. Also loadable in Node for testing.
 *
 * Every check returns an explainable signal — education is part of the product.
 * Preserves original MIT license and adds Student Shield detection heuristics.
 */
(function (global) {
  "use strict";

  const ENGINE_VERSION = "2.0.0-student-shield";

  // ---- reference data -------------------------------------------------------

  // Brands commonly impersonated in phishing, mapped to their real domains.
  const BRANDS = {
    paypal: ["paypal.com", "paypal-objects.com"],
    amazon: ["amazon.com"],
    apple: ["apple.com", "icloud.com"],
    google: ["google.com", "accounts.google.com", "withgoogle.com", "gstatic.com",
      "googleapis.com", "googleusercontent.com", "googleblog.com", "google.org",
      "jigsaw.google.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com", "office.com",
      "office365.com", "office.net", "sharepoint.com", "microsoftonline.com",
      "live.net", "msft.net", "bing.com", "xbox.com"],
    netflix: ["netflix.com"],
    facebook: ["facebook.com", "fb.com", "meta.com"],
    instagram: ["instagram.com"],
    twitter: ["twitter.com", "x.com"],
    linkedin: ["linkedin.com"],
    chase: ["chase.com"],
    wellsfargo: ["wellsfargo.com"],
    bankofamerica: ["bankofamerica.com"],
    coinbase: ["coinbase.com"],
    binance: ["binance.com"],
    dhl: ["dhl.com"],
    fedex: ["fedex.com"],
    usps: ["usps.com"],
    irs: ["irs.gov"],
    steam: ["steampowered.com", "steamcommunity.com"],
    discord: ["discord.com", "discordapp.com"],
    roblox: ["roblox.com"],
    tiktok: ["tiktok.com"],
    whatsapp: ["whatsapp.com"],
    dropbox: ["dropbox.com"],
    adobe: ["adobe.com"],
    zoom: ["zoom.us"],
    ebay: ["ebay.com"],
    spotify: ["spotify.com"],
    ledger: ["ledger.com"],
    trezor: ["trezor.io"],
    metamask: ["metamask.io"],
    trustwallet: ["trustwallet.com"],
    kraken: ["kraken.com"],
    blockchain: ["blockchain.com"],
    revolut: ["revolut.com"],
    wise: ["wise.com", "transferwise.com"],
    citibank: ["citibank.com", "citi.com"],
    capitalone: ["capitalone.com"],
    americanexpress: ["americanexpress.com", "aexp.com", "amex.com"],
    venmo: ["venmo.com"],
    cashapp: ["cash.app"],
    telegram: ["telegram.org", "t.me"],
    snapchat: ["snapchat.com"],
    protonmail: ["protonmail.com", "proton.me"],
    openai: ["openai.com", "chatgpt.com"],
    github: ["github.com"],
    etsy: ["etsy.com"],
    // Student & Educational Platforms
    canvas: ["instructure.com"],
    blackboard: ["blackboard.com"],
    moodle: ["moodle.org", "moodle.com"],
    brightspace: ["d2l.com", "brightspace.com"],
    coursera: ["coursera.org"],
    edx: ["edx.org"],
    studentaid: ["studentaid.gov", "ed.gov"],
    harvard: ["harvard.edu"],
    mit: ["mit.edu"],
    stanford: ["stanford.edu"],
    berkeley: ["berkeley.edu"],
    oxford: ["ox.ac.uk"],
    cambridge: ["cam.ac.uk"],
    columbia: ["columbia.edu"],
    nyu: ["nyu.edu"],
    ucla: ["ucla.edu"]
  };

  // Common university / higher-ed keywords
  const UNIVERSITY_KEYWORDS = [
    "harvard", "mit", "stanford", "berkeley", "oxford", "cambridge",
    "columbia", "nyu", "ucla", "cornell", "princeton", "yale",
    "campus", "university", "college", "faculty", "student", "alumni",
    "registrar", "bursar", "blackboard", "canvas", "brightspace"
  ];

  // Student-specific financial / scholarship lures
  const STUDENT_AID_KEYWORDS = [
    "fafsa", "student-loan", "loan-forgiveness", "tuition-refund",
    "student-bursary", "campus-grant", "emergency-aid", "pell-grant",
    "scholarship-award", "financialaid", "tuition-assistance"
  ];

  // Does a normalized host label (hyphens stripped) contain the brand?
  function labelHasBrand(norm, b) {
    if (norm === b) return true;
    if (norm === b + "s") return false; // dictionary plural (apples.com)
    if (b.length <= 4) {
      if (norm.startsWith(b)) return true;
      return norm.endsWith(b) && PATH_KEYWORDS.includes(norm.slice(0, -b.length));
    }
    if (norm.length >= b.length + 2 && norm.includes(b)) return true;
    const dn = deobfuscate(norm);
    if (dn !== norm && dn.length >= b.length + 2 && dn.includes(b)) return true;
    const sq = (s) => s.replace(/(.)\1+/g, "$1");
    const sb = sq(b);
    return sq(norm).length >= sb.length + 2 && sq(norm).includes(sb);
  }

  // Free/disposable and frequently-abused TLDs.
  const SUS_TLDS = new Set([
    "tk", "ml", "ga", "cf", "gq", "top", "buzz", "cam", "rest", "quest",
    "monster", "icu", "click", "country", "stream", "download", "loan",
    "racing", "win", "bid", "date", "review", "party", "gdn", "men",
    "work", "zip", "mov", "cfd", "info", "help", "live", "site", "online",
    "store", "shop", "app", "sbs", "mom", "lol", "pics", "skin", "deals",
    "agency", "bar", "cc", "cyou", "link", "casa"
  ]);

  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "s.id", "bit.do", "soo.gd", "clck.ru", "v.gd", "goo.su", "qrco.de",
    "s4w.in", "g5.lu", "hotm.io", "ln.run", "short.io", "gt.tc", "fr.gd",
    "ur.ly", "zi.ht"
  ]);

  // Credential-theft vocabulary in URL paths.
  const PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "billing", "confirm", "suspend", "unlock",
    "wallet", "recover", "password", "credential", "authenticate",
    "webscr", "oauth", "validate", "reauth", "websc", "wp-admin",
    "wp-content", "wp-includes", "components/com_", "myaccount",
    "student-login", "campus-sso", "portal-auth", "student-verify"
  ];

  // Scare/urgency phrases scanned in visible page text.
  const URGENCY_PHRASES = [
    "verify your account", "account suspended", "account has been suspended",
    "unusual activity", "suspicious activity", "confirm your identity",
    "immediately", "within 24 hours", "24 hours", "limited time",
    "act now", "urgent", "final notice", "last warning", "will be closed",
    "will be suspended", "legal action", "avoid suspension", "restricted",
    "unauthorized", "locked your account", "verify now", "update your payment",
    "payment declined", "claim your prize", "you have won", "congratulations",
    "wire transfer", "gift card", "bitcoin", "crypto", "refund"
  ];

  // Student-specific panic phrases
  const STUDENT_URGENCY_PHRASES = [
    "student account deactivation", "student account suspended",
    "student email will be terminated", "campus portal access suspended",
    "library access will be terminated", "confirm your student status immediately",
    "tuition overdue account termination", "office 365 student license expiration",
    "duo mfa verification required", "student bursary claim pending",
    "urgent student aid disbursement", "academic hold placed on account"
  ];

  const COMMON_SLD_WORDS = /^(mail|email|shop|store|news|blog|app|web|site|online|cloud|data|tech|media|group|inc|corp|home|my|the|get|go)/;

  // Confusable character map: visually-similar chars folded to ASCII.
  const CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ո": "n", "օ": "o", "α": "a", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "κ": "k", "μ": "m", "χ": "x"
  };
  const MULTI_CONFUSABLES = [
    [/rn/g, "m"], [/vv/g, "w"], [/cl/g, "d"], [/nn/g, "n"]
  ];

  const IP_HOST = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$/i;

  // ---- helpers --------------------------------------------------------------

  function levenshtein(a, b) {
    if (a === b) return 0;
    const m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(
          prev[j] + 1,
          cur[j - 1] + 1,
          prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
        );
      }
      prev = cur;
    }
    return prev[n];
  }

  function shannon(s) {
    if (!s.length) return 0;
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    return Object.values(freq).reduce(
      (e, f) => e - (f / s.length) * Math.log2(f / s.length), 0
    );
  }

  function deobfuscate(sld) {
    let out = "";
    for (const ch of sld.toLowerCase()) out += CONFUSABLES[ch] || ch;
    for (const [re, rep] of MULTI_CONFUSABLES) out = out.replace(re, rep);
    return out;
  }

  const EXEC_EXTS = [".exe", ".msi", ".apk", ".scr", ".bat", ".cmd", ".ps1",
    ".jar", ".vbs", ".js", ".iso", ".dmg", ".pkg", ".hta"];

  const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;

  const DOMAIN_BAIT = ["login", "signin", "signon", "verify", "account",
    "secure", "support", "billing", "confirm", "auth", "wallet", "webscr",
    "password", "credential", "update", "recovery", "unlock", "suspend",
    "secur", "client", "compte", "banque", "colis", "livraison", "suivi",
    "facture", "impot", "remboursement", "expir", "oferta", "oferte",
    "verific", "atendimento", "acesso", "empresa", "payee", "transfer",
    "cancel", "sms", "gift", "limitedtime", "myaccount", "invoice", "refund",
    "payout", "registro", "cita", "formulario", "cliente", "cuenta", "seguridad",
    "verificar", "pedido", "envio", "rastreo", "premio", "commande",
    "studentlogin", "campusauth", "portal-sso"];

  const FREE_HOSTS = ["github.io", "blogspot.com", "weebly.com", "amplifyapp.com",
    "workers.dev", "pages.dev", "web.app", "firebaseapp.com", "netlify.app",
    "vercel.app", "herokuapp.com", "wordpress.com", "wixsite.com", "glitch.me",
    "replit.app", "repl.co", "surge.sh", "fly.dev", "onrender.com", "trycloudflare.com",
    "ngrok.io", "ngrok-free.app", "000webhostapp.com", "sites.google.com",
    "godaddysites.com", "webflow.io", "framer.website", "gitbook.io", "wix.com",
    "site123.me", "carrd.co", "canva.site", "notion.site", "linktr.ee"];

  function isGenuineEduDomain(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    return h.endsWith(".edu") || h.endsWith(".edu.au") || h.endsWith(".edu.sg") ||
           h.endsWith(".edu.my") || h.endsWith(".edu.cn") || h.endsWith(".edu.in") ||
           h.endsWith(".ac.uk") || h.endsWith(".edu.br");
  }

  function registrable(host) {
    const parts = host.split(".");
    if (parts.length < 2) return host;
    const second = parts[parts.length - 2];
    if (second.length <= 3 && ["co", "com", "net", "org", "gov", "ac", "edu"].includes(second)) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function sldOf(host) {
    const reg = registrable(host);
    return reg.split(".")[0];
  }

  function tldOf(host) {
    const parts = host.split(".");
    return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
  }

  function isBrandDomain(host) {
    return Object.values(BRANDS).flat().some(
      (d) => host === d || host.endsWith("." + d)
    );
  }

  // Official interactive cybersecurity education, training & phishing simulation platforms
  const SECURITY_AWARENESS_DOMAINS = new Set([
    "phishingquiz.withgoogle.com",
    "beinternetawesome.withgoogle.com",
    "quiz.opendns.com",
    "antiphishing.org",
    "cisa.gov",
    "ftc.gov"
  ]);

  function isSecurityAwarenessPlatform(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    if (SECURITY_AWARENESS_DOMAINS.has(h)) return true;
    for (const d of SECURITY_AWARENESS_DOMAINS) {
      if (h === d || h.endsWith("." + d)) return true;
    }
    return false;
  }

  function signal(id, weight, severity, title, detail, category = "security") {
    return { id, weight, severity, category, title, detail };
  }

  // ---- URL analysis -----------------------------------------------------------

  function analyzeUrl(raw) {
    try {
      const signals = [];
      let url;
      const input = String(raw || "").trim();
      if (!input) {
        return createFallback(input, "empty input");
      }
      try {
        url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(input) ? input : "http://" + input);
      } catch (e) {
        return createFallback(input, "unparseable URL");
      }

      // Non-HTTP(S) schemes
      if (url.protocol === "data:") {
        signals.push(signal("data-uri", 55, "high", "data: URI link",
          "data: URLs smuggle a whole payload inside the link itself — a known phishing channel."));
        return finalize(signals, input, url);
      }
      if (["javascript:", "vbscript:", "file:", "about:", "blob:"].includes(url.protocol)) {
        signals.push(signal("danger-scheme", 55, "high", `Dangerous scheme "${url.protocol}"`,
          "This link executes content directly — never part of a legitimate login flow."));
        return finalize(signals, input, url);
      }

      const host = url.hostname.toLowerCase();
      const path = (url.pathname + url.search).toLowerCase();
      const sld = sldOf(host);
      const tld = tldOf(host);
      const reg = registrable(host);
      const subCount = host.split(".").length - reg.split(".").length;
      const subs = host === reg ? [] :
        host.slice(0, host.length - reg.length - 1).split(".").filter(Boolean);
      const freeHost = FREE_HOSTS.find((f) => host === f || host.endsWith("." + f));
      const brandLabels = (freeHost ? [] : [sld]).concat(subs).map((l) => l.replace(/-/g, ""));

      // Transport & scheme
      if (url.protocol === "http:") {
        signals.push(signal("http", 12, "med", "No encryption (HTTP)",
          "Credentials sent over HTTP are transmitted in plaintext without SSL protection."));
      } else if (!/^https?:$/.test(url.protocol)) {
        signals.push(signal("scheme", 15, "med", `Unusual scheme "${url.protocol}"`,
          "Non-HTTP(S) schemes in links are rare in legitimate student messages."));
      }
      if (url.protocol === "https:") {
        signals.push(signal("https", -5, "good", "Encrypted connection (HTTPS)",
          "HTTPS is baseline hygiene — but does not by itself prove legitimacy."));
      }

      // Host shape
      if (IP_HOST.test(host)) {
        signals.push(signal("ip-host", 35, "high", "Raw IP address as hostname",
          "Legitimate student or banking services almost never host logins on a bare IP."));
      }
      if (url.username || url.password) {
        signals.push(signal("at-sign", 50, "high", "Credentials embedded in URL",
          `The 'user@host' trick hides the real destination — the true host is '${host}'.`));
      }
      if (host.includes("xn--") || url.href.includes("xn--")) {
        signals.push(signal("punycode", 40, "high", "Punycode/IDN hostname",
          "Internationalized domains can render lookalike homoglyph characters."));
      }
      if (SUS_TLDS.has(tld)) {
        signals.push(signal("tld", 18, "med", `High-abuse TLD ".${tld}"`,
          "This TLD is cheap or disposable and statistically over-represented in phishing scams."));
      }
      if (SHORTENERS.has(reg)) {
        signals.push(signal("shortener", 15, "med", "URL shortener",
          "Short links conceal the true destination — expand before trusting campus notices."));
      }
      if (subCount >= 3) {
        signals.push(signal("subdomains", 15, "med", `${subCount} nested subdomains`,
          "Long chains like 'harvard.edu.login.secure.evil.com' bury the real domain."));
      } else if (subCount === 2) {
        signals.push(signal("subdomains", 6, "low", "Multiple subdomains",
          "Slightly unusual nesting — verify the true registrable domain."));
      }
      const hyphens = (sld.match(/-/g) || []).length;
      if (hyphens >= 2) {
        signals.push(signal("hyphens", 10, "low", `${hyphens} hyphens in domain`,
          "Stuffing like 'student-portal-verify' is a classic phishing tell."));
      }
      if (input.length > 100) {
        signals.push(signal("length", 8, "low", `Very long URL (${input.length} chars)`,
          "Overlong URLs are often used to push the real domain out of the browser address bar."));
      }

      // ================= STUDENT SHIELD HEURISTICS =================
      // 1. Fake .EDU / University Spoofing in Host
      const isGenuineEdu = isGenuineEduDomain(host);
      if (!isGenuineEdu) {
        // Did attacker embed .edu in subdomain or hyphenated domain on a non-edu TLD?
        const hasEduLabel = subs.some((s) => s === "edu" || s.startsWith("edu-") || s.endsWith("-edu"));
        const hasUniKeyword = UNIVERSITY_KEYWORDS.some((kw) => host.includes(kw));
        const eduInSubdomainOrHost = host.includes(".edu.") || host.includes("-edu.") || hasEduLabel;

        if (eduInSubdomainOrHost) {
          signals.push(signal("student-edu-spoof", 42, "high",
            "University / .EDU Domain Spoofing",
            `'${host}' places '.edu' or university names inside subdomains on an unofficial commercial domain (${reg}).`,
            "impersonation"));
        } else if (hasUniKeyword && (host.includes("portal") || host.includes("login") || host.includes("sso") || host.includes("auth"))) {
          signals.push(signal("student-portal-lookalike", 38, "high",
            "University Portal / SSO Impersonation",
            `Domain '${host}' mimics a university single-sign-on or campus portal on a non-educational domain.`,
            "impersonation"));
        }
      } else {
        // Bonus for genuine .edu domain
        signals.push(signal("edu-official", -15, "good",
          "Official educational institution domain (.edu)",
          "Domain is officially registered under an accredited educational institution registry."));
      }

      // 2. Student Financial Aid / FAFSA / Tuition Refund lures
      const matchedAidKeyword = STUDENT_AID_KEYWORDS.find((k) => host.includes(k) || path.includes(k));
      if (matchedAidKeyword && !host.endsWith(".gov") && !isGenuineEdu) {
        signals.push(signal("student-financial-aid", 40, "high",
          "Student Financial Aid / Tuition Refund Lure",
          `URL references student financial aid or tuition refunds ('${matchedAidKeyword}') on an unofficial commercial host.`,
          "impersonation"));
      }
      // =============================================================

      // Brand impersonation
      if (!isBrandDomain(host)) {
        const deob = deobfuscate(sld);
        for (const [brand] of Object.entries(BRANDS)) {
          if (brand.length <= 3) continue;
          if (deob === brand + "s") continue;
          if (deob.length < brand.length && brand.includes(deob)) continue;
          const dist = levenshtein(deob, brand);
          if (deob !== brand && dist > 0 && dist <= (brand.length <= 6 ? 1 : 2)) {
            signals.push(signal("typosquat", 45, "high",
              `Lookalike of "${brand}" (edit distance ${dist})`,
              `'${host}' differs subtly from the genuine ${BRANDS[brand][0]} — a typosquat.`,
              "impersonation"));
            break;
          }
          if (dist === 0 && deob !== sld) {
            signals.push(signal("homoglyph", 45, "high",
              `Homoglyph impersonation of "${brand}"`,
              `'${sld}' uses lookalike characters to spell '${brand}'.`,
              "impersonation"));
            break;
          }
        }

        // brand name embedded in hostname while real domain is something else
        for (const [brand, domains] of Object.entries(BRANDS)) {
          const owned = domains.some((d) => host === d || host.endsWith("." + d));
          if (!owned && brandLabels.some((l) => labelHasBrand(l, brand))) {
            signals.push(signal("brand-in-host", 35, "high",
              `"${brand}" appears in hostname but domain is '${reg}'`,
              "Attackers prepend brand names as subdomains to look legitimate.",
              "impersonation"));
            break;
          }
        }
      }

      // Credential-bait words in domain
      const INSTITUTIONAL = ["gov", "edu", "mil", "govt", "ac"];
      if (!isBrandDomain(host) && !INSTITUTIONAL.includes(tld)) {
        const hostBait = brandLabels.filter((l) => DOMAIN_BAIT.some((k) =>
          l.includes(k) && !(l.startsWith(k) && l.length <= k.length + 3) &&
          !(k === "banque" && l.startsWith("banquet"))));
        if (hostBait.length) {
          signals.push(signal("domain-bait", Math.min(24, 8 + hostBait.length * 8), "med",
            `Credential-bait words in domain (${hostBait.slice(0, 3).join(", ")})`,
            "Words like 'login/verify/support' baked into the hostname are phishing scaffolding.",
            "structure"));
        }
      }

      // Path keywords
      const kwHits = PATH_KEYWORDS.filter((k) => path.includes(k));
      if (kwHits.length && !isBrandDomain(host)) {
        signals.push(signal("path-kw", Math.min(20, 6 + kwHits.length * 4), "med",
          `Credential-bait keywords in path (${kwHits.slice(0, 4).join(", ")})`,
          "Login/verify/billing lures on an unrelated domain are a phishing pattern."));
      }

      // Executable download in path
      const execExt = EXEC_EXTS.find((e) => url.pathname.toLowerCase().endsWith(e));
      if (execExt) {
        signals.push(signal("exec-download", 40, "high",
          `Direct download of executable (${execExt})`,
          "Links that download executable programs from unexpected sites are drive-by malware risks."));
      }

      // Victim email in URL
      if (EMAIL_RE.test(path) || EMAIL_RE.test(url.search)) {
        signals.push(signal("email-in-url", 25, "med",
          "An email address is embedded in the URL",
          "Phishers pre-fill lures with your student email address to make the page appear legitimate."));
      }

      // Non-standard port
      if (url.port && !["80", "443"].includes(url.port)) {
        signals.push(signal("odd-port", 15, "med", `Non-standard port :${url.port}`,
          "Legitimate student login pages almost never run on alternative network ports."));
      }

      // High-entropy domain
      if (sld.length >= 12 && shannon(sld) > 3.6 && !COMMON_SLD_WORDS.test(sld)) {
        signals.push(signal("entropy", 12, "med", "Random-looking domain name",
          `High character entropy (${shannon(sld).toFixed(1)} bits) suggests a generated domain.`));
      }

      // Benign bonus
      if (isBrandDomain(host)) {
        signals.push(signal("brand-official", -20, "good",
          "Official brand domain", "Hostname belongs to a known verified service."));
      }
      if (isSecurityAwarenessPlatform(host)) {
        signals.push(signal("security-education", -25, "good",
          "Verified Cybersecurity Training / Awareness Platform",
          "Domain is an official educational security awareness testbed (e.g. Google Phishing Quiz).",
          "security"));
      }

      return finalize(signals, input, url);
    } catch (err) {
      return createFallback(raw, err.message);
    }
  }

  // ---- page/DOM analysis ------------------------------------------------------

  function analyzePage(snap) {
    try {
      if (!snap || typeof snap !== "object") return [];
      const signals = [];
      let pageHost = "";
      try { pageHost = new URL(snap.url).hostname.toLowerCase(); } catch (e) {}

      const isEdu = isGenuineEduDomain(pageHost);
      const isBrand = isBrandDomain(pageHost);
      const isSecEdu = isSecurityAwarenessPlatform(pageHost);
      const isTrusted = isEdu || isBrand || isSecEdu;

      for (const f of snap.forms || []) {
        if (!f.hasPassword) continue;
        if (!f.action) {
          if (!isTrusted) {
            signals.push(signal("form-noaction", 15, "med",
              "Password form with no declared destination",
              "The submit target is set dynamically — a common credential-harvest pattern."));
          }
          continue;
        }
        let a;
        try { a = new URL(f.action, snap.url); } catch (e) { continue; }
        if (a.protocol === "http:") {
          signals.push(signal("form-http", 45, "high",
            "Password submitted over plaintext HTTP",
            "Anything you type here is sent unencrypted over the network.",
            "credential"));
        } else if (a.hostname.toLowerCase() !== pageHost &&
                   registrable(a.hostname.toLowerCase()) !== registrable(pageHost) &&
                   !(isBrand && isBrandDomain(a.hostname.toLowerCase()))) {
          signals.push(signal("form-xdomain", 45, "high",
            `Password form posts to an external domain (${a.hostname})`,
            "Legitimate campus logins almost never transmit student passwords cross-site.",
            "credential"));
        }
      }

      // Student ID / University credential harvesting check
      const studentInputTerms = (snap.inputNames || []).filter((n) =>
        /student.?id|studentid|campus.?id|netid|banner.?id|matriculation|student.?email|university.?id/i.test(n));
      if (studentInputTerms.length && !isEdu && !isSecEdu && (snap.passwordFields || 0) > 0) {
        signals.push(signal("student-portal-lookalike", 45, "high",
          `Harvesting Student Credentials (${studentInputTerms.slice(0, 2).join(", ")})`,
          "A password form requesting student ID / university credentials was found on a non-educational domain.",
          "credential"));
      }

      // General sensitive fields
      const sensitive = (snap.inputNames || []).filter((n) =>
        /ssn|social.?sec|cvv|cvc|card.?num|otp|one.?time|pin|seed.?phrase|private.?key|routing.?num|bank.?account/i.test(n));
      if (sensitive.length && !isTrusted) {
        signals.push(signal("sensitive-fields", 30, "high",
          `Page asks for sensitive financial/identity data (${sensitive.slice(0, 3).join(", ")})`,
          "Direct requests for SSNs, bank accounts, or OTPs deserve high scrutiny.",
          "credential"));
      }

      // Hidden iframes
      if ((snap.hiddenIframes || 0) > 0 && !isTrusted) {
        signals.push(signal("hidden-iframe", 20, "med",
          `${snap.hiddenIframes} hidden iframe(s)`,
          "Invisible frames are used for clickjacking and covert redirects."));
      }

      // External links ratio
      if ((snap.totalLinks || 0) >= 10 && (snap.externalLinks || 0) / snap.totalLinks > 0.9 && !isTrusted) {
        signals.push(signal("ext-links", 10, "low",
          "Nearly all links point off-site",
          "Throwaway phishing pages often link out to genuine resources to mimic legitimacy."));
      }

      // Text analysis: Urgency & Student Panic
      if (!isTrusted) {
        const text = (snap.text || "").toLowerCase();
        const studentUrgentHits = STUDENT_URGENCY_PHRASES.filter((p) => text.includes(p));
        if (studentUrgentHits.length) {
          signals.push(signal("student-urgency", 30, "high",
            `Student panic language detected ("${studentUrgentHits[0]}")`,
            "Threats of student account deactivation or loss of campus access are primary student phishing levers.",
            "urgency"));
        }

        const hits = URGENCY_PHRASES.filter((p) => text.includes(p));
        if (hits.length && !studentUrgentHits.length) {
          signals.push(signal("urgency", Math.min(30, 8 + hits.length * 5), "med",
            `Pressure language detected (${hits.length} phrases)`,
            `e.g. "${hits[0]}" — urgency and fear are core social-engineering levers.`,
            "urgency"));
        }
      }

      return signals;
    } catch (err) {
      console.warn("PhishLens engine page analysis caught error:", err);
      return [];
    }
  }

  // ---- scoring and shared result formatting ----------------------------------

  function categorizeThreat(signals, score) {
    if (score < 15) return "safe";
    const ids = new Set(signals.map((s) => s.id));
    if (ids.has("student-edu-spoof") || ids.has("student-portal-lookalike")) {
      return "student_portal_spoof";
    }
    if (ids.has("student-financial-aid") || ids.has("student-bursary-scam")) {
      return "financial_aid_scam";
    }
    if (ids.has("form-http") || ids.has("form-xdomain") || ids.has("cred-lookalike") || ids.has("sensitive-fields")) {
      return "credential_harvest";
    }
    if (ids.has("typosquat") || ids.has("brand-in-host") || ids.has("homoglyph")) {
      return "typosquat";
    }
    if (ids.has("student-urgency") || ids.has("urgency")) {
      return "urgency_scam";
    }
    return score >= 40 ? "suspicious_structure" : "caution_general";
  }

  function generateSummary(level, threatCategory, host, topSignal, isSecEdu) {
    if (isSecEdu) {
      return "Verified cybersecurity awareness & phishing simulation quiz (official educational resource).";
    }
    if (level === "likely safe") {
      return "No suspicious phishing indicators detected. Site appears standard.";
    }
    switch (threatCategory) {
      case "student_portal_spoof":
        return `High risk: ${host || "This site"} appears to be an unofficial clone spoofing a university or student portal.`;
      case "financial_aid_scam":
        return `Danger: Fake student aid or tuition refund lure detected. Do not submit banking credentials or SSN.`;
      case "credential_harvest":
        return `Critical warning: Page forms transmit passwords unencrypted or off-domain. Never enter passwords here!`;
      case "typosquat":
        return `Deceptive domain: ${host || "This site"} uses typosquatting or lookalike characters to impersonate a legitimate service.`;
      case "urgency_scam":
        return `Social engineering detected: Page uses aggressive account deactivation threats to manipulate students.`;
      default:
        return topSignal ? `${topSignal.title}. Exercise caution before entering credentials.` : "Multiple suspicious indicators detected.";
    }
  }

  function getStudentAdvice(threatCategory, host, isSecEdu) {
    if (isSecEdu) {
      return [
        "This is an official interactive cybersecurity quiz. Practice identifying phishing indicators safely!",
        "Notice how simulated emails in the quiz use deceptive subdomains, fake senders, or lookalike links.",
        "Remember: real campus IT and banks will never send emails asking you to confirm passwords via link."
      ];
    }

    const defaultAdvice = [
      "Always check the browser address bar to confirm the domain ends with your university's genuine .edu address.",
      "Campus IT and student services will never email asking you to verify your password or Duo MFA codes.",
      "Never input your Student ID or SSO credentials on forms hosted on external or commercial domains."
    ];

    if (threatCategory === "student_portal_spoof") {
      return [
        `Do not enter your Student ID or campus login on '${host}'.`,
        "Access your university portal directly by typing your school's verified URL or through official bookmarks.",
        "If you already entered credentials, immediately change your university password from an official campus computer."
      ];
    }
    if (threatCategory === "financial_aid_scam") {
      return [
        "Official student financial aid and FAFSA updates only occur on studentaid.gov or your institution's .edu site.",
        "Never share student debit cards, bank account numbers, or SSN for an unexpected grant or bursary.",
        "Contact your university Financial Aid office directly to confirm any disbursement notice."
      ];
    }
    return defaultAdvice;
  }

  function finalize(signals, input, url) {
    const raw = signals.reduce((s, x) => s + x.weight, 0);
    const score = Math.max(0, Math.min(100, Math.round(raw)));
    const level =
      score >= 70 ? "dangerous" :
      score >= 40 ? "suspicious" :
      score >= 15 ? "caution" : "likely safe";

    const host = url ? url.hostname : "";
    const sortedSignals = signals.sort((a, b) => b.weight - a.weight);
    const threatCategory = categorizeThreat(sortedSignals, score);
    const topSignal = sortedSignals.find((s) => s.weight > 0) || sortedSignals[0];
    const isSecEdu = sortedSignals.some((s) => s.id === "security-education");
    const summary = generateSummary(level, threatCategory, host, topSignal, isSecEdu);

    const isStudentTargeted = threatCategory.startsWith("student_") ||
      threatCategory === "financial_aid_scam" ||
      isSecEdu ||
      sortedSignals.some((s) => s.id.startsWith("student-"));

    const detectedTargets = [];
    if (isSecEdu) {
      detectedTargets.push("Cybersecurity Training & Phishing Awareness Quiz");
    }
    if (sortedSignals.some((s) => s.id === "student-edu-spoof" || s.id === "student-portal-lookalike")) {
      detectedTargets.push("University SSO / Campus Portal");
    }
    if (sortedSignals.some((s) => s.id === "student-financial-aid")) {
      detectedTargets.push("Financial Aid / Bursary");
    }
    if (sortedSignals.some((s) => s.id === "student-urgency")) {
      detectedTargets.push("Campus Account Access");
    }

    return {
      ok: true,
      version: ENGINE_VERSION,
      timestamp: Date.now(),
      url: input,
      input,
      host,
      score,
      level,
      isHighRisk: score >= 70,
      threatCategory,
      summary,
      signals: sortedSignals,
      pageSignals: [],
      studentProtection: {
        isStudentTargeted,
        detectedTargets,
        advice: getStudentAdvice(threatCategory, host, isSecEdu)
      },
      error: null
    };
  }

  function createFallback(input, errorMessage) {
    let host = "";
    try { if (input) host = new URL(input).hostname; } catch (e) {}
    return {
      ok: false,
      version: ENGINE_VERSION,
      timestamp: Date.now(),
      url: input || "",
      input: input || "",
      host,
      score: 0,
      level: "unknown",
      isHighRisk: false,
      threatCategory: "safe",
      summary: errorMessage ? `Scan limited: ${errorMessage}` : "Unable to analyze site.",
      signals: [],
      pageSignals: [],
      studentProtection: {
        isStudentTargeted: false,
        detectedTargets: [],
        advice: ["Verify site authenticity manually before entering sensitive credentials."]
      },
      error: errorMessage || null
    };
  }

  function analyze(raw, snap) {
    try {
      const urlResult = analyzeUrl(raw);
      if (snap) {
        const extra = analyzePage(snap);
        urlResult.pageSignals = extra;
        urlResult.signals = urlResult.signals.concat(extra)
          .sort((a, b) => b.weight - a.weight);
        const re = finalize(urlResult.signals, urlResult.input,
          (() => { try { return new URL(urlResult.input); } catch (e) { return null; } })());
        urlResult.score = re.score;
        urlResult.level = re.level;
        urlResult.isHighRisk = re.isHighRisk;
        urlResult.threatCategory = re.threatCategory;
        urlResult.summary = re.summary;
        urlResult.studentProtection = re.studentProtection;
      }
      return urlResult;
    } catch (err) {
      return createFallback(raw, err.message);
    }
  }

  const api = {
    version: ENGINE_VERSION,
    analyzeUrl,
    analyzePage,
    analyze,
    BRANDS,
    levenshtein,
    deobfuscate,
    createFallback
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.PhishLens = api;
})(typeof window !== "undefined" ? window : globalThis);
