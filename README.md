# Utkarsh Ki Fish 🛡️🐟

**Real-time, private, explainable phishing protection engineered for students — running 100% locally in your browser with zero network calls, zero tracking, and zero paid API dependencies.**

Base Repository Attribution: Built upon the open-source foundation of [Georgefifth/phishlens](https://github.com/Georgefifth/phishlens) under the original MIT License.

---

## 1. Executive Summary & Problem

Students and university communities are among the highest-volume targets for modern social engineering and credential theft:
- **Campus Portal & SSO Spoofing**: Attackers deploy deceptive subdomains (e.g. `harvard.edu.login-portal.net` or `campus-sso-verify.xyz`) to harvest student IDs, NetIDs, and Duo MFA logins.
- **Financial Aid & Tuition Relief Scams**: Attackers exploit tuition deadlines, FAFSA disbursements, and emergency bursary promises to steal student banking details and Social Security numbers.
- **LMS Account Panic**: Urgent notices claiming student email or Canvas accounts will be deactivated within 24 hours pressure students into submitting credentials on malicious forms.

Traditional browser protection either leaks browsing activity to cloud vendor APIs or provides an opaque warning that fails to educate the student. **PhishLens Student Shield** operates 100% client-side via deterministic local heuristics, providing instant defense, explainable threat signals, and tailored student safety advice.

---

## 2. Team Structure & Code Ownership

Developed under a coordinated 90-minute hackathon sprint structure (documented in [`TEAM.md`](TEAM.md)):

| Member | Role | Key Contributions | Key Files |
|---|---|---|---|
| **Technical Lead** | Architecture & Service Worker Lead | Manifest V3 permissions, background service worker lifecycle, desktop notifications, threat deduplication, error resilience boundaries & test runner. | `extension/manifest.json`<br>`extension/background.js`<br>`test/e2e-test.js` |
| **Parth** | Detection Engine Lead | Heuristic engine enhancements, university `.edu` domain spoofing detection, student financial aid/bursary scam radar, shared result schema. | `engine.js`<br>`extension/engine.js`<br>`shared-schema.js` |
| **Arnav** | UI/UX & Integration Lead | In-page Shadow DOM warning banner, interactive extension popup interface, student protection guidance, reproducible demo testbed. | `extension/content.js`<br>`extension/popup.html`<br>`extension/popup.js`<br>`web/demo/` |

---

## 3. Architecture & Capabilities

```
phishlens/
├── engine.js              # Pure JavaScript detection engine (zero deps, works in Node, MV3, and Web)
├── shared-schema.js       # Shared analysis result schema, validation, and safe error fallbacks
├── TEAM.md                # Hackathon team ownership matrix & result format specs
├── test/
│   └── e2e-test.js        # Automated verification suite (35/35 passing tests)
├── extension/             # Manifest V3 Chrome Extension
│   ├── manifest.json      # MV3 configuration (notifications, tabs, storage, activeTab)
│   ├── background.js      # Background service worker: badges, desktop notifications, deduplication
│   ├── content.js         # Content script: DOM snapshot scanner & isolated Shadow DOM warning banner
│   ├── popup.html/js      # Browser action popup: active tab verdict + URL sandbox analyzer
│   └── icons/             # 16px, 32px, 48px, 128px extension icons
└── web/                   # Demo testbed & standalone analyzer
    ├── index.html         # Live interactive web analyzer with student threat samples
    └── demo/              # Safe simulated phishing pages (no credential exfiltration)
        ├── student-portal-phish.html  # University SSO credential harvest & panic lure
        ├── campus-aid-scam.html       # Emergency grant & tuition relief scam
        ├── paypal-verify.html         # Brand lookalike & HTTP form demonstration
        └── legit-university.html      # Clean control page (verifies false-positive resistance)
```

### Detection Engine Capabilities (100% Local Heuristics)
1. **University / .EDU Domain Spoofing**: Identifies deceptive subdomains parking `.edu` or university names within commercial TLDs (`harvard.edu.login-portal.net`).
2. **Student Financial Aid & Bursary Radar**: Detects unauthorized third-party sites soliciting banking credentials or SSNs under FAFSA, tuition refund, or student grant pretexts.
3. **Campus Credential Harvesting Traps**: Scans DOM forms for password fields posting off-domain, over unencrypted HTTP, or targeting Student IDs / NetIDs.
4. **Student Urgency & Social Engineering**: Flags panic triggers ("student account deactivation", "library access suspended", "confirm enrollment in 24 hours").
5. **Typosquatting & Homoglyphs**: Levenshtein distance matching against major brands and educational platforms (`canvas`, `blackboard`, `moodle`, `coursera`).
6. **URL Forensics**: Abused TLDs, IP hostnames, credential embedding (`user@host`), URL shorteners, entropy analysis, and vowel-less random hostnames.

---

## 4. Shared Result Format Specification (`PhishLensResult`)

All components conform to a strict standardized schema:

```json
{
  "ok": true,
  "version": "2.0.0-student-shield",
  "timestamp": 1729000000000,
  "url": "https://harvard.edu.login-portal.net/verify",
  "host": "harvard.edu.login-portal.net",
  "score": 94,
  "level": "dangerous",
  "isHighRisk": true,
  "threatCategory": "student_portal_spoof",
  "summary": "High risk: harvard.edu.login-portal.net appears to be an unofficial clone spoofing a university or student portal.",
  "signals": [
    {
      "id": "student-edu-spoof",
      "weight": 42,
      "severity": "high",
      "category": "impersonation",
      "title": "University / .EDU Domain Spoofing",
      "detail": "'harvard.edu.login-portal.net' places '.edu' or university names inside subdomains on an unofficial commercial domain."
    }
  ],
  "studentProtection": {
    "isStudentTargeted": true,
    "detectedTargets": ["University SSO / Campus Portal"],
    "advice": [
      "Do not enter your Student ID or campus login on this domain.",
      "Access university portals directly via your school's verified .edu bookmarks."
    ]
  },
  "error": null
}
```

---

## 5. Desktop Notifications & Deduplication Engine

- **High-Risk Threshold**: Desktop notifications fire when `score >= 70` (or `level === "dangerous"`).
- **Anti-Spam Deduplication**: Notifications are indexed by `${tabId}:${normalizedUrl}:${threatCategory}`.
- **Cooldown & Escalation**: Identical alerts for the same tab and threat are suppressed within a 5-minute cooldown window, unless threat severity substantially escalates.
- **Fail-Safe Operation**: All DOM parsing, message passing, and notification calls are protected by error boundaries — failures never crash the extension or user browsing.

---

## 6. Installation & Chrome Setup (60 Seconds)

### Step 1: Open Chrome Extensions
1. Launch Google Chrome.
2. Open the URL: `chrome://extensions` (or navigate via Settings > Extensions).
3. In the top-right corner, toggle **Developer mode** to **ON**.

### Step 2: Load the Unpacked Extension
1. Click the **Load unpacked** button in the top toolbar.
2. Browse to this repository folder and select the `extension/` directory (`d:/projects/HACKATHON/TCS/extension/`).
3. **PhishLens Student Shield** will appear in your Chrome toolbar with its icon.

---

## 7. Reproducible Demo & Testing Workflow

### Option A: Run the Automated Verification Suite
Run the comprehensive 35-test automated suite directly via Node:
```bash
node test/e2e-test.js
```
Expected output: **35 / 35 TESTS PASSED** (validates MV3 permissions, detection heuristics, shared schema, deduplication, and error boundaries).

### Option B: Test Live Demo Pages in Chrome
1. Start the local test server:
   ```bash
   node test-server.js
   ```
2. Open Chrome to `http://localhost:8080/index.html`.
3. Test the following scenarios:
   - **Scenario 1: Fake University SSO Login (`demo/student-portal-phish.html`)**
     - *Expected result*: In-page red warning banner automatically slides down (`Score 90-100 Dangerous`), extension badge displays `!`, desktop security notification triggers, and student guidance advises against submitting student credentials.
   - **Scenario 2: Emergency Student Bursary Scam (`demo/campus-aid-scam.html`)**
     - *Expected result*: In-page warning banner flags high-risk financial aid lure soliciting banking details and SSN.
   - **Scenario 3: Control Page — Clean University Portal (`demo/legit-university.html`)**
     - *Expected result*: Extension badge remains clean/green (`Score 0 Likely Safe`), verifying zero false positives.
   - **Scenario 4: Extension Popup Analyzer**
     - Click the extension icon in the Chrome toolbar.
     - Paste any suspicious link (e.g. `https://harvard.edu.login-portal.net`) into the analyzer.
     - Instant explained verdict and student safety recommendations display immediately.

---

## 8. License & Attribution

This project is licensed under the **MIT License**.
- Preserves all original copyright and licensing from [Georgefifth/phishlens](https://github.com/Georgefifth/phishlens).
- Developed for the 2026 Student Cybersecurity Hackathon Challenge.
- Zero paid API keys, zero tracking, zero external databases.
