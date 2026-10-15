# NETRA 👁 — Network Eye for Threat Recognition & Analysis

**Real-time, 100% local phishing detection engine. Zero network calls, zero tracking, zero paid API dependencies.**

> NETRA watches every URL and page you visit — locally, instantly, privately. Pure heuristic intelligence built for students and university communities.

---

## 1. Problem Statement

Students and university communities face sophisticated phishing attacks:
- **Campus Portal & SSO Spoofing**: Attackers deploy deceptive subdomains (e.g. `harvard.edu.login-portal.net`) to harvest Student IDs, NetIDs, and MFA logins.
- **Financial Aid Scams**: FAFSA, tuition refund, and emergency bursary lures steal banking details and SSNs.
- **Credential Panic Attacks**: Urgent "account deactivation in 24h" notices pressure students into malicious forms.

Traditional browser protection leaks browsing activity to cloud APIs or provides opaque warnings. **NETRA** operates 100% client-side with deterministic local heuristics, delivering instant defense, explainable threat signals, and tailored safety advice.

---

## 2. Team

| Member | Role | Key Files |
|--------|------|-----------|
| **Technical Lead** | Architecture & Service Worker | `extension/manifest.json`, `extension/background.js` |
| **Parth** | Detection Engine | `engine.js`, `shared-schema.js` |
| **Arnav** | UI/UX & Integration | `extension/content.js`, `extension/popup.html`, `web/` |

---

## 3. Architecture

```
TCS/
├── engine.js              # Pure JS detection engine (zero deps, runs in Node, MV3, and Web)
├── shared-schema.js       # Shared result schema, validation, and error fallbacks
├── extension/             # Manifest V3 Chrome Extension
│   ├── manifest.json      # MV3 config (notifications, tabs, storage, activeTab)
│   ├── background.js      # Background service worker: badges, desktop alerts, deduplication
│   ├── content.js         # Content script: DOM scanner & isolated Shadow DOM warning banner
│   ├── popup.html/js      # Browser action popup: live tab verdict + URL inspector
│   └── icons/             # 16px, 32px, 48px, 128px NETRA eye icons
└── web/
    └── index.html         # Live interactive web analyzer
```

---

## 4. Detection Capabilities (100% Local)

1. **University / .EDU Domain Spoofing** — Identifies deceptive subdomains parking `.edu` within commercial TLDs.
2. **Student Financial Aid Radar** — Detects FAFSA, tuition refund, and student grant lures on unauthorized domains.
3. **Credential Harvest Form Scanner** — DOM forms with password fields posting off-domain, over HTTP, or targeting NetIDs.
4. **Student Urgency Language** — Flags panic triggers like "account deactivation", "library access suspended", "confirm enrollment in 24h".
5. **Typosquatting & Homoglyphs** — Levenshtein distance vs 60+ brands; catches Cyrillic lookalikes, l→1, o→0, rn→m.
6. **URL Forensics** — Abused TLDs, IP hostnames, `@` credential embedding, URL shorteners, entropy analysis.

---

## 5. Result Schema

```json
{
  "ok": true,
  "score": 94,
  "level": "dangerous",
  "host": "harvard.edu.login-portal.net",
  "summary": "High risk: university portal spoofing detected.",
  "signals": [
    {
      "id": "student-edu-spoof",
      "severity": "high",
      "title": "University / .EDU Domain Spoofing",
      "detail": "'.edu' or university name placed inside a commercial domain."
    }
  ],
  "studentProtection": {
    "isStudentTargeted": true,
    "advice": ["Do not enter your Student ID or campus login on this domain."]
  }
}
```

---

## 6. Install in Chrome (60 Seconds)

1. Open `chrome://extensions`
2. Toggle **Developer mode** ON
3. Click **Load unpacked** → select the `extension/` folder
4. The NETRA 👁 icon appears in your toolbar

---

## 7. Desktop Notifications & Deduplication

- Fires when `score >= 70` (dangerous / suspicious)
- Deduplicated by `${tabId}:${url}:${threatCategory}` — no spam
- 5-minute cooldown per tab/threat pair
- All operations wrapped in error boundaries — never crashes the extension

---

## 8. License

MIT License — Zero paid APIs, zero tracking, zero external databases.
