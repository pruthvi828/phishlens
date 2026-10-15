/*
 * NETRA Shield — client-side phishing risk analysis engine.
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
    paypal: ["paypal.com", "paypal-objects.com", "paypal.me"],
    amazon: [
      "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca",
      "amazon.co.jp", "amazon.fr", "amazon.it", "amazon.es", "amazon.com.au",
      "amazon.com.mx", "amazon.com.br", "amazon.cn", "amazon.nl", "amazon.sg",
      "amazon.ae", "amazon.sa", "amazon.pl", "amazon.se", "amazon.eg",
      "amazon.com.tr", "amazon.com.be", "amazon.ie", "media-amazon.com",
      "ssl-images-amazon.com", "primevideo.com", "a2z.com", "aboutamazon.com",
      "amazonaws.com", "aws.amazon.com", "images-amazon.com"
    ],
    apple: ["apple.com", "icloud.com", "appleid.apple.com", "cdn-apple.com", "mzstatic.com"],
    google: [
      "google.com", "google.co.in", "google.co.uk", "google.de", "google.ca",
      "google.co.jp", "google.fr", "google.it", "google.es", "google.com.au",
      "google.com.br", "google.nl", "accounts.google.com", "withgoogle.com",
      "gstatic.com", "googleapis.com", "googleusercontent.com", "googleblog.com",
      "google.org", "jigsaw.google.com", "googlevideo.com", "gmail.com"
    ],
    youtube: [
      "youtube.com", "youtu.be", "ytimg.com", "youtube-nocookie.com", "yt.be"
    ],
    facebook: [
      "facebook.com", "fb.com", "meta.com", "messenger.com", "fbcdn.net",
      "fbsbx.com", "meta.me", "workplace.com"
    ],
    microsoft: [
      "microsoft.com", "live.com", "outlook.com", "office.com",
      "office365.com", "office.net", "sharepoint.com", "microsoftonline.com",
      "live.net", "msft.net", "bing.com", "xbox.com", "msn.com", "skype.com",
      "teams.microsoft.com", "microsoftstream.com"
    ],
    netflix: ["netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"],
    instagram: ["instagram.com", "threads.net", "cdninstagram.com"],
    twitter: ["twitter.com", "x.com", "t.co", "twimg.com", "x.ai"],
    linkedin: ["linkedin.com", "licdn.com"],
    reddit: ["reddit.com", "redd.it", "redditstatic.com", "redditmedia.com"],
    wikipedia: ["wikipedia.org", "wikimedia.org", "wiktionary.org", "wikidata.org"],
    github: ["github.com", "githubassets.com", "github.blog"],
    discord: ["discord.com", "discordapp.com", "discord.gg", "discordapp.net"],
    twitch: ["twitch.tv", "ttvnw.net", "jtvnw.net"],
    tiktok: ["tiktok.com", "tiktokcdn.com", "byteoversea.com"],
    whatsapp: ["whatsapp.com", "wa.me"],
    stackoverflow: [
      "stackoverflow.com", "stackexchange.com", "sstatic.net", "askubuntu.com",
      "superuser.com", "serverfault.com"
    ],
    yahoo: ["yahoo.com", "yahoo.co.jp", "yimg.com"],
    ebay: [
      "ebay.com", "ebay.co.uk", "ebay.de", "ebay.in", "ebay.ca", "ebay.com.au",
      "ebaystatic.com", "ebayimg.com"
    ],
    pinterest: ["pinterest.com", "pinimg.com"],
    quora: ["quora.com", "quoracdn.net"],
    spotify: ["spotify.com", "scdn.co", "spotifycdn.com"],
    dropbox: ["dropbox.com", "dropboxstatic.com"],
    adobe: ["adobe.com", "adobe.io", "behance.net"],
    zoom: ["zoom.us", "zoom.com"],
    openai: ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
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
    roblox: ["roblox.com"],
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
    "registrar", "bursar", "blackboard", "canvas", "brightspace",
    "admissions", "financial aid", "fafsa", "student aid", "moodle",
    "student portal", "student affairs", "dean of students"
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

  // Scare/urgency phrases scanned in visible page text AND email bodies.
  const URGENCY_PHRASES = [
    "verify your account", "account suspended", "account has been suspended",
    "unusual activity", "suspicious activity", "confirm your identity",
    "immediately", "within 24 hours", "24 hours", "limited time",
    "act now", "urgent", "final notice", "last warning", "will be closed",
    "will be suspended", "legal action", "avoid suspension", "restricted",
    "unauthorized", "locked your account", "verify now", "update your payment",
    "payment declined", "claim your prize", "you have won", "congratulations",
    "wire transfer", "gift card", "bitcoin", "crypto", "refund",
    // Email-specific additions
    "click here to verify", "click the link below", "do not ignore",
    "action required", "your account will be deleted", "failure to respond",
    "we detected a login", "sign in to secure", "important security notice",
    "unusual sign-in", "we noticed a new login", "reply with your password",
    "kindly update", "confirm your details", "your invoice is attached",
    "reactivate your account", "account on hold", "pending verification"
  ];

  // Student-specific panic phrases (page text + email body)
  const STUDENT_URGENCY_PHRASES = [
    "student account deactivation", "student account suspended",
    "student email will be terminated", "campus portal access suspended",
    "library access will be terminated", "confirm your student status immediately",
    "tuition overdue account termination", "office 365 student license expiration",
    "duo mfa verification required", "student bursary claim pending",
    "urgent student aid disbursement", "academic hold placed on account",
    // Email-targeted student lures
    "your .edu email will expire", "scholarship application is on hold",
    "fafsa verification required", "student loan confirmation",
    "campus account will be disabled", "reset your university password",
    "registrar requires verification", "bursar payment failure",
    "account will be suspended", "student account suspension",
    "financial aid hold", "university account will be suspended",
    "tuition hold", "billing hold"
  ];

  // Phishing-favoured subject line keywords (used in analyzeEmail)
  const PHISH_SUBJECT_KEYWORDS = [
    "urgent", "action required", "account suspended", "verify now",
    "important notice", "security alert", "unusual activity", "invoice",
    "final notice", "password expir", "confirm your", "click to activate",
    "you have a pending", "unclaimed", "reward", "winner", "congratulations",
    "re:", "fwd:", "[external]", "[spam]",
    "student aid", "fafsa", "tuition", "scholarship", "financial aid",
    "campus account", "university email", "duo mfa", "office 365"
  ];

  // Suspicious email attachment extensions
  const PHISH_ATTACH_EXTS = [
    ".exe", ".msi", ".apk", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".hta", ".scr", ".iso", ".doc", ".docm",
    ".xls", ".xlsm", ".zip", ".7z", ".rar", ".html", ".htm"
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
    if (!host) return false;
    const h = host.toLowerCase();
    for (const domains of Object.values(BRANDS)) {
      for (const d of domains) {
        if (h === d || h.endsWith("." + d)) return true;
      }
    }
    return false;
  }

  function getMatchedBrand(host) {
    if (!host) return null;
    const h = host.toLowerCase();
    for (const [brand, domains] of Object.entries(BRANDS)) {
      for (const d of domains) {
        if (h === d || h.endsWith("." + d)) return brand;
      }
    }
    return null;
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
      if (!isBrandDomain(host)) {
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
          if (brand.length <= 3) continue;
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
      if (sld.length >= 12 && shannon(sld) > 3.6 && !COMMON_SLD_WORDS.test(sld) && !isBrandDomain(host)) {
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
      console.warn("NETRA engine page analysis caught error:", err);
      return [];
    }
  }

  // ---- email phishing analysis -----------------------------------------------

  function analyzeEmail(email) {
    try {
      if (!email || typeof email !== "object") {
        return createEmailFallback("", "no email data provided");
      }
      const signals = [];

      // Parse sender
      const rawFrom = String(email.from || "").trim();
      const fromMatch = rawFrom.match(/^(.+?)\s*<([^>]+)>\s*$/);
      const displayName = fromMatch ? fromMatch[1].replace(/["']/g, "").trim() : "";
      const fromAddr    = fromMatch ? fromMatch[2].trim() : rawFrom;
      const fromDomain  = fromAddr.includes("@")
        ? fromAddr.split("@").pop().toLowerCase()
        : fromAddr.toLowerCase();

      // Display-name brand spoofing (e.g. "PayPal Support" <evil@scam.com>)
      if (displayName) {
        const dispNorm = deobfuscate(displayName.toLowerCase().replace(/[^a-z0-9]/g, ""));
        for (const [brand, domains] of Object.entries(BRANDS)) {
          if (brand.length <= 3) continue;
          const isOfficial = domains.some(
            (d) => fromDomain === d || fromDomain.endsWith("." + d)
          );
          if (!isOfficial && dispNorm.includes(brand)) {
            signals.push(signal("email-display-name-spoof", 45, "high",
              "Display name impersonates \"" + brand + "\" (sender: " + fromAddr + ")",
              "The email claims to be from '" + brand + "' but actually arrives from '" + fromAddr + "'. Attackers fake display names because mail clients show only the friendly name.",
              "impersonation"));
            break;
          }
        }
      }

      // From-domain typosquat / homoglyph
      if (fromDomain && !isBrandDomain(fromDomain)) {
        const fSld  = fromDomain.split(".")[0];
        const fDeob = deobfuscate(fSld);
        for (const [brand] of Object.entries(BRANDS)) {
          if (brand.length <= 3) continue;
          const dist = levenshtein(fDeob, brand);
          if (dist > 0 && dist <= (brand.length <= 6 ? 1 : 2)) {
            signals.push(signal("email-sender-typosquat", 50, "high",
              "Sender domain typosquats \"" + brand + "\" (got: " + fromDomain + ")",
              "'" + fromDomain + "' is one character away from the real " + brand + " domain — a classic spoofing trick. Delete without clicking.",
              "impersonation"));
            break;
          }
          if (dist === 0 && fDeob !== fSld) {
            signals.push(signal("email-sender-homoglyph", 50, "high",
              "Sender domain uses homoglyphs to imitate \"" + brand + "\" (" + fromDomain + ")",
              "Visually identical characters (e.g. Cyrillic vs Latin) are used to bypass spam filters.",
              "impersonation"));
            break;
          }
        }
      }

      // Disposable/temp sender domain
      const DISPOSABLE = new Set([
        "mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com",
        "throwam.com", "sharklasers.com", "yopmail.com", "trashmail.com",
        "maildrop.cc", "dispostable.com", "fakeinbox.com", "getairmail.com",
        "spamgourmet.com", "discard.email", "filzmail.com", "spamex.com"
      ]);
      if (DISPOSABLE.has(fromDomain)) {
        signals.push(signal("email-disposable-sender", 35, "high",
          "Sender uses disposable/temp email service (" + fromDomain + ")",
          "Legitimate universities and companies never send official email from disposable domains.",
          "structure"));
      }

      // Reply-To mismatch
      const replyTo = String(email.replyTo || "").trim();
      if (replyTo) {
        const rtM = replyTo.match(/<([^>]+)>/);
        const rtAddr   = rtM ? rtM[1].trim() : replyTo;
        const rtDomain = rtAddr.includes("@") ? rtAddr.split("@").pop().toLowerCase() : "";
        if (rtDomain && rtDomain !== fromDomain) {
          signals.push(signal("email-reply-to-mismatch", 35, "high",
            "Reply-To domain differs from sender (" + rtDomain + " vs " + fromDomain + ")",
            "When replies go to a different domain than the sender, attackers intercept your response without you noticing.",
            "structure"));
        }
      }

      // .EDU spoofing in From domain
      if (!isGenuineEduDomain(fromDomain)) {
        const hasEduLabel = fromDomain.includes(".edu.") || fromDomain.includes("-edu.") ||
          fromDomain.split(".").some((l) => l === "edu");
        const hasUniInDisplay = displayName &&
          UNIVERSITY_KEYWORDS.some((kw) => displayName.toLowerCase().includes(kw));
        if (hasEduLabel) {
          signals.push(signal("email-edu-spoof", 45, "high",
            "Sender fakes a .edu domain (" + fromDomain + ")",
            "The sender domain contains '.edu' in a non-root position — a known trick to impersonate universities.",
            "impersonation"));
        } else if (hasUniInDisplay) {
          signals.push(signal("email-uni-display-spoof", 30, "med",
            "Display name references a university but sender is not .edu (" + fromAddr + ")",
            "Phishers use your university name as a display name while sending from Gmail or other free domains.",
            "impersonation"));
        }
      }

      // SPF / DKIM / DMARC authentication failures
      const spf   = String(email.receivedSpf  || "").toLowerCase();
      const dkim  = String(email.dkimResult   || "").toLowerCase();
      const dmarc = String(email.dmarcResult  || "").toLowerCase();
      if (spf.includes("fail") || spf.includes("softfail")) {
        signals.push(signal("email-spf-fail", 30, "high",
          "SPF authentication failed",
          "The sending server is not authorised by the From domain — high probability the address is forged.",
          "structure"));
      }
      if (dkim.includes("fail") || dkim.includes("none")) {
        signals.push(signal("email-dkim-fail", 20, "med",
          "DKIM signature missing or failed",
          "Email content is not cryptographically verified by the sender domain.",
          "structure"));
      }
      if (dmarc.includes("fail") || dmarc.includes("reject") || dmarc.includes("quarantine")) {
        signals.push(signal("email-dmarc-fail", 25, "high",
          "DMARC policy violation",
          "The sender domain explicitly states this mail should be rejected or quarantined.",
          "structure"));
      }

      // Subject line analysis
      const subject = String(email.subject || "").toLowerCase();
      if (subject) {
        const subHits = PHISH_SUBJECT_KEYWORDS.filter((k) => subject.includes(k));
        if (subHits.length >= 2) {
          signals.push(signal("email-phish-subject",
            Math.min(30, 10 + subHits.length * 5), "high",
            "High-risk subject line (" + subHits.slice(0, 3).join(", ") + ")",
            "Multiple phishing-associated keywords in the subject line are a strong social engineering signal.",
            "urgency"));
        } else if (subHits.length === 1) {
          signals.push(signal("email-phish-subject", 8, "low",
            "Mildly suspicious subject keyword (\"" + subHits[0] + "\")",
            "A single urgency keyword can be legitimate but warrants scrutiny of the rest of the email.",
            "urgency"));
        }
      }

      // Body analysis
      const rawBody  = String(email.body || "");
      const bodyText = rawBody.replace(/<[^>]+>/g, " ").toLowerCase();

      const studentUrgentHits = STUDENT_URGENCY_PHRASES.filter((p) => bodyText.includes(p));
      if (studentUrgentHits.length) {
        signals.push(signal("email-student-urgency", 30, "high",
          "Student panic language in email body (\"" + studentUrgentHits[0] + "\")",
          "Threats about student account suspension or financial aid holds are the #1 student phishing tactic.",
          "urgency"));
      }
      const urgencyHits = URGENCY_PHRASES.filter((p) => bodyText.includes(p));
      if (urgencyHits.length && !studentUrgentHits.length) {
        signals.push(signal("email-urgency",
          Math.min(25, 5 + urgencyHits.length * 5), "med",
          "Urgency/pressure language in body (" + urgencyHits.length + " phrases)",
          "e.g. \"" + urgencyHits[0] + "\" — phishers manufacture panic to bypass careful thinking.",
          "urgency"));
      }

      // Password request in body
      if (/reply.{0,30}(password|credential|pin|otp|passcode)/i.test(rawBody) ||
          /send.{0,30}(password|credential|pin|otp)/i.test(rawBody)) {
        signals.push(signal("email-password-request", 55, "high",
          "Email asks you to reply with your password or PIN",
          "No legitimate service ever asks for your password via email — this is always a credential theft attempt.",
          "credential"));
      }

      // Extract & analyse embedded links
      const hrefRe = /href=["']([^"']+)["']/gi;
      const extracted = [];
      let hm;
      while ((hm = hrefRe.exec(rawBody)) !== null) extracted.push(hm[1]);
      const bareRe = /https?:\/\/[^\s"'<>)]{4,}/gi;
      const bare   = bodyText.match(bareRe) || [];
      const allLinks = [...new Set([...(email.links || []), ...extracted, ...bare])];

      let suspLinkCount = 0;
      const suspLinkResults = [];
      for (const link of allLinks.slice(0, 20)) {
        try {
          const lr = analyzeUrl(link);
          if (lr.score >= 15) { suspLinkCount++; suspLinkResults.push(lr); }
        } catch (e) { /* skip */ }
      }
      if (suspLinkCount > 0) {
        const topLink = suspLinkResults.slice().sort((a, b) => b.score - a.score)[0];
        signals.push(signal("email-suspicious-links",
          Math.min(50, 15 + suspLinkCount * 10), "high",
          suspLinkCount + " suspicious link(s) found in email body",
          "e.g. '" + topLink.host + "' scored " + topLink.score + "/100 — " + topLink.summary,
          "structure"));
      }

      // Display text vs href mismatch
      const anchorRe = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]{4,80})<\/a>/gi;
      let mismatchCount = 0;
      let am;
      while ((am = anchorRe.exec(rawBody)) !== null) {
        const href = am[1];
        const txt  = am[2].trim().toLowerCase();
        if (/^https?:\/\//i.test(txt)) {
          try {
            const dh = new URL(txt.trim()).hostname.toLowerCase();
            const hh = new URL(href.trim()).hostname.toLowerCase();
            if (dh !== hh && registrable(dh) !== registrable(hh)) mismatchCount++;
          } catch (e) { /* skip */ }
        }
      }
      if (mismatchCount > 0) {
        signals.push(signal("email-link-mismatch", 40, "high",
          mismatchCount + " link(s) show a fake URL hiding the real destination",
          "The visible link text and actual href point to different domains — a reliable phishing indicator.",
          "structure"));
      }

      // Dangerous attachments
      const attachments = email.attachments || [];
      const dangerAttach = attachments.filter((fn) =>
        PHISH_ATTACH_EXTS.some((ext) => String(fn).toLowerCase().endsWith(ext))
      );
      if (dangerAttach.length) {
        signals.push(signal("email-dangerous-attach",
          Math.min(45, 20 + dangerAttach.length * 10), "high",
          "Suspicious attachment(s): " + dangerAttach.slice(0, 3).join(", "),
          "Executable or macro-enabled Office documents in unsolicited emails are the leading malware delivery vector.",
          "structure"));
      }

      // Benign authentication signals
      if (spf.includes("pass")) {
        signals.push(signal("email-spf-pass", -8, "good",
          "SPF authentication passed",
          "The sending server is authorised by the From domain."));
      }
      if (dkim.includes("pass")) {
        signals.push(signal("email-dkim-pass", -8, "good",
          "DKIM signature verified",
          "Email content is cryptographically signed and unaltered."));
      }
      if (dmarc.includes("pass")) {
        signals.push(signal("email-dmarc-pass", -5, "good",
          "DMARC policy passed",
          "Sender domain authentication policy is satisfied."));
      }

      // Finalize
      const rawScore = signals.reduce((s, x) => s + x.weight, 0);
      const score = Math.max(0, Math.min(100, Math.round(rawScore)));
      const level =
        score >= 70 ? "dangerous" :
        score >= 40 ? "suspicious" :
        score >= 15 ? "caution" : "likely safe";
      const isHighRisk = score >= 70;
      const sortedSignals = signals.slice().sort((a, b) => b.weight - a.weight);
      const topSig = sortedSignals.find((s) => s.weight > 0);

      let summary;
      if (level === "likely safe") {
        summary = "No strong phishing indicators found in this email.";
      } else if (score >= 70) {
        summary = topSig
          ? "HIGH RISK: " + topSig.title + ". Do not click any links or open attachments."
          : "Multiple strong phishing indicators. Treat this email as malicious.";
      } else {
        summary = topSig
          ? "Suspicious email: " + topSig.title + ". Verify through official channels before acting."
          : "Some suspicious indicators found — exercise caution.";
      }

      const isStudentTargeted = sortedSignals.some((s) =>
        s.id.startsWith("email-student") ||
        s.id === "email-edu-spoof" ||
        s.id === "email-uni-display-spoof");

      return {
        ok: true,
        version: ENGINE_VERSION,
        timestamp: Date.now(),
        type: "email",
        from: fromAddr,
        fromDomain,
        displayName,
        subject: email.subject || "",
        score,
        level,
        isHighRisk,
        threatCategory: isStudentTargeted ? "student_email_phish"
          : isHighRisk ? "credential_harvest"
          : score >= 40 ? "suspicious_email" : "safe",
        summary,
        signals: sortedSignals,
        suspiciousLinks: suspLinkResults.slice().sort((a, b) => b.score - a.score)
          .map((r) => ({ url: r.url, score: r.score, level: r.level, summary: r.summary })),
        studentProtection: {
          isStudentTargeted,
          detectedTargets: isStudentTargeted ? ["Student Email / Campus Account"] : [],
          advice: isStudentTargeted ? [
            "Campus IT will never email asking you to reset passwords via a link — call the helpdesk to verify.",
            "Forward suspicious .edu-impersonating emails to your university abuse or security team.",
            "Check the actual sender address (not just the display name) by hovering or expanding it."
          ] : [
            "Never click links in unexpected emails — navigate directly to the site by typing its address.",
            "Check the sender domain carefully for subtle typos (e.g. 'arnazon.com' vs 'amazon.com').",
            "Legitimate services never ask for passwords, PINs, or OTPs via email."
          ]
        },
        error: null
      };
    } catch (err) {
      return createEmailFallback("", err.message);
    }
  }

  function createEmailFallback(from, errorMessage) {
    return {
      ok: false,
      version: ENGINE_VERSION,
      timestamp: Date.now(),
      type: "email",
      from: from || "",
      fromDomain: "",
      displayName: "",
      subject: "",
      score: 0,
      level: "unknown",
      isHighRisk: false,
      threatCategory: "safe",
      summary: errorMessage ? "Email scan limited: " + errorMessage : "Unable to analyze email.",
      signals: [],
      suspiciousLinks: [],
      studentProtection: { isStudentTargeted: false, detectedTargets: [], advice: [] },
      error: errorMessage || null
    };
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

  function generateSummary(level, threatCategory, host, topSignal, isSecEdu, isBrand) {
    if (isSecEdu) {
      return "Verified cybersecurity awareness & phishing simulation quiz (official educational resource).";
    }
    if (isBrand && level === "likely safe") {
      const brand = getMatchedBrand(host);
      const bName = brand ? brand.charAt(0).toUpperCase() + brand.slice(1) : "Official";
      return `Verified official ${bName} domain (likely safe). No suspicious phishing indicators detected.`;
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
    const host = url ? url.hostname.toLowerCase() : "";
    const isBrand = isBrandDomain(host);
    const isEdu = isGenuineEduDomain(host);
    const isSecEdu = signals.some((s) => s.id === "security-education");

    // Critical real exploits: e.g. cross-domain password posting or unencrypted password form
    const hasCriticalExploit = signals.some((s) =>
      s.id === "form-http" || s.id === "form-xdomain" || s.id === "exec-download"
    );

    let score;
    let level;
    if ((isBrand || isEdu || isSecEdu) && !hasCriticalExploit) {
      score = 0;
      level = "likely safe";
    } else {
      const raw = signals.reduce((s, x) => s + x.weight, 0);
      score = Math.max(0, Math.min(100, Math.round(raw)));
      level =
        score >= 70 ? "dangerous" :
        score >= 40 ? "suspicious" :
        score >= 15 ? "caution" : "likely safe";
    }

    const sortedSignals = signals.sort((a, b) => b.weight - a.weight);
    const threatCategory = score === 0 ? "safe" : categorizeThreat(sortedSignals, score);
    const topSignal = sortedSignals.find((s) => s.weight > 0) || sortedSignals[0];
    const summary = generateSummary(level, threatCategory, host, topSignal, isSecEdu, isBrand);

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
    analyzeEmail,
    BRANDS,
    isBrandDomain,
    getMatchedBrand,
    levenshtein,
    deobfuscate,
    createFallback
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.NETRA = api;
})(typeof window !== "undefined" ? window : globalThis);
