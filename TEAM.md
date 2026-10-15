# NETRA Student Shield — Hackathon Team Matrix & Shared Specs

## 1. Team Ownership & Responsibilities

| Role | Name | Responsibilities | Assigned Files |
|------|------|-------------------|----------------|
| **Technical Lead** | Lead Engineer | • Overall architecture & Manifest V3 compliance<br>• Background service worker lifecycle<br>• Desktop notifications & deduplication engine<br>• Extension stability, error boundaries & testing | `extension/manifest.json`<br>`extension/background.js`<br>`test/` |
| **Detection Lead** | Parth | • Heuristic detection engine & regex rules<br>• Student threat corpus (LMS spoofing, `.edu` impersonation, financial aid lures)<br>• Brand & homoglyph reference data<br>• Shared analysis result schema definition | `engine.js`<br>`extension/engine.js`<br>`shared-schema.js` |
| **UI/UX & Integration Lead** | Arnav | • Content script automatic scanner<br>• In-page Shadow DOM warning banner<br>• Interactive popup extension UI<br>• Demo pages for student phishing scenarios | `extension/content.js`<br>`extension/popup.html`<br>`extension/popup.js`<br>`web/demo/` |

---

## 2. Shared Result Format Specification (`PhishLensResult`)

All components (`engine.js`, `content.js`, `background.js`, `popup.js`, and demo suites) must strictly adhere to this standardized JSON schema.

```typescript
interface PhishLensResult {
  ok: boolean;                         // True if analysis completed, false if graceful error fallback
  version: "2.0.0-student-shield";     // Engine version identifier
  timestamp: number;                   // Unix timestamp (ms) of analysis
  url: string;                         // Full analyzed URL
  host: string;                        // Extracted hostname (e.g. "portal.university.edu.phish.com")
  score: number;                       // Risk score 0 to 100
  level: "dangerous" | "suspicious" | "caution" | "likely safe" | "unknown";
  isHighRisk: boolean;                 // true if score >= 70 (triggers desktop notification)
  threatCategory: string;              // Primary threat category:
                                       // 'student_portal_spoof' | 'credential_harvest' | 'financial_aid_scam' |
                                       // 'typosquat' | 'homoglyph' | 'urgency_scam' | 'suspicious_structure' | 'safe'
  summary: string;                     // 1-sentence plain-English verdict for students
  signals: PhishSignal[];              // Sorted list of all detected signals (highest weight first)
  pageSignals: PhishSignal[];          // Signals detected specifically from page DOM
  studentProtection: {
    isStudentTargeted: boolean;        // Whether page specifically targets students / university users
    detectedTargets: string[];         // e.g. ["Canvas LMS", "Financial Aid", "University SSO"]
    advice: string[];                  // Actionable security steps for students
  };
  error?: string | null;               // Error message if ok === false
}

interface PhishSignal {
  id: string;                          // Unique signal identifier (e.g. 'student-edu-spoof')
  weight: number;                      // Score impact (-10 to +50)
  severity: "high" | "med" | "low" | "good"; // Display severity styling
  category: "impersonation" | "credential" | "urgency" | "structure" | "security";
  title: string;                       // Short title (e.g. "University .edu Spoofing Detected")
  detail: string;                      // Detailed educational rationale for students
}
```

### Risk Level Thresholds
- **Dangerous (`score >= 70`)**: Red badge, automatic top warning banner, high-priority desktop notification.
- **Suspicious (`score >= 40`)**: Orange badge, in-page advisory banner.
- **Caution (`score >= 15`)**: Yellow badge, popup notice.
- **Likely Safe (`score < 15`)**: Green badge, safe status.

---

## 3. Communication & Message Passing Protocol

### Content Script -> Background Service Worker:
```javascript
chrome.runtime.sendMessage({
  type: "pl-score",
  result: phishLensResult // Complete PhishLensResult object
});
```

### Background Service Worker Handling:
1. Validates message against `PhishLensResult` format.
2. Updates tab badge color and text (`!` for high risk, score number for medium).
3. Evaluates deduplication cache: `${tabId}:${url}:${result.threatCategory}:${Math.floor(result.score/10)}`.
4. If `isHighRisk === true` and not recently notified, fires `chrome.notifications.create`.
5. Caches current tab verdict for popup query.

### Popup -> Content Script / Background:
- Sends `{ type: "pl-get-result" }` to retrieve cached tab result.
- Displays immediate visual gauge and student protection advice.

---

## 4. Team Git Synchronization Protocol (Non-Destructive Pull & Push)

To maintain absolute code integrity and prevent overwriting teammates' work:

1. **Pull Before Starting Any Task:**
   ```bash
   git pull origin student-shield
   ```
2. **Never Overwrite Teammates' Code:**
   - Preserve teammate implementations in their assigned modules (`engine.js`, `content.js`, `popup.html`, `demo/`).
   - Reference teammates' functions and patterns rather than replacing them.
   - Only edit shared integration interfaces when strictly required to wire components together.
3. **Pre-Push Validation:**
   - Always run the automated verification suite before committing:
     ```bash
     node test/e2e-test.js
     ```
   - All tests must pass (35/35) to ensure integrations do not crash the extension.
4. **Push to Team Fork Branch:**
   ```bash
   git add .
   git commit -m "feat(module): description of non-breaking integration"
   git push origin student-shield
   ```

