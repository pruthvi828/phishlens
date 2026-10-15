/**
 * PhishLens Student Shield — Shared Result Format & Validation
 * Standard schema shared across engine.js, content.js, background.js, and popup.js.
 */
(function (global) {
  "use strict";

  const SCHEMA_VERSION = "2.0.0-student-shield";

  const RISK_LEVELS = {
    DANGEROUS: "dangerous",     // score >= 70
    SUSPICIOUS: "suspicious",   // score >= 40
    CAUTION: "caution",         // score >= 15
    SAFE: "likely safe",        // score < 15
    UNKNOWN: "unknown"
  };

  /**
   * Determine primary threat category based on detected signals and score
   */
  function categorizeThreat(signals, score) {
    if (score < 15) return "safe";
    const ids = new Set((signals || []).map((s) => s.id));
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
    if (ids.has("urgency")) {
      return "urgency_scam";
    }
    return score >= 40 ? "suspicious_structure" : "caution_general";
  }

  /**
   * Generates a 1-sentence plain-English verdict summary for students
   */
  function generateSummary(level, threatCategory, topSignal, host) {
    if (level === RISK_LEVELS.SAFE) {
      return "No suspicious phishing patterns detected. This site appears standard.";
    }
    switch (threatCategory) {
      case "student_portal_spoof":
        return `Warning: ${host || "This site"} appears to be spoofing a university or student portal to steal login credentials.`;
      case "financial_aid_scam":
        return `High risk: Suspicious student financial aid or tuition refund lure detected. Never provide banking or SSN details.`;
      case "credential_harvest":
        return `Critical danger: Password form sends credentials off-domain or unencrypted. Do not enter passwords!`;
      case "typosquat":
        return `Deceptive domain: ${host || "This domain"} mimics a well-known brand or campus service.`;
      case "urgency_scam":
        return `Suspicious pressure: High concentration of panic/deadline language typical of social engineering.`;
      default:
        return topSignal ? `${topSignal.title}. Exercise caution before entering personal data.` : "Multiple suspicious indicators detected.";
    }
  }

  /**
   * Create an empty or error fallback result that guarantees the extension will never crash
   */
  function createSafeFallbackResult(url, errorMessage) {
    let host = "";
    try {
      if (url) host = new URL(url).hostname;
    } catch (e) {
      host = String(url || "");
    }

    return {
      ok: false,
      version: SCHEMA_VERSION,
      timestamp: Date.now(),
      url: url || "",
      host: host,
      score: 0,
      level: RISK_LEVELS.UNKNOWN,
      isHighRisk: false,
      threatCategory: "safe",
      summary: errorMessage ? `Inspection limited: ${errorMessage}` : "Page could not be fully analyzed.",
      signals: [],
      pageSignals: [],
      studentProtection: {
        isStudentTargeted: false,
        detectedTargets: [],
        advice: ["Always verify website URLs manually before entering credentials."]
      },
      error: errorMessage || null
    };
  }

  /**
   * Validate and conform any result object to the shared schema standard
   */
  function formatResult(rawResult) {
    if (!rawResult || typeof rawResult !== "object") {
      return createSafeFallbackResult("", "Invalid result object passed");
    }

    const score = Math.max(0, Math.min(100, Math.round(Number(rawResult.score) || 0)));
    const level =
      score >= 70 ? RISK_LEVELS.DANGEROUS :
      score >= 40 ? RISK_LEVELS.SUSPICIOUS :
      score >= 15 ? RISK_LEVELS.CAUTION :
      RISK_LEVELS.SAFE;

    const signals = Array.isArray(rawResult.signals) ? rawResult.signals.map((s) => ({
      id: String(s.id || "signal"),
      weight: Number(s.weight) || 0,
      severity: ["high", "med", "low", "good"].includes(s.severity) ? s.severity : "med",
      category: s.category || "security",
      title: String(s.title || "Detected anomaly"),
      detail: String(s.detail || "")
    })) : [];

    signals.sort((a, b) => b.weight - a.weight);

    const threatCategory = rawResult.threatCategory || categorizeThreat(signals, score);
    const topSignal = signals.find((s) => s.weight > 0) || signals[0];
    const summary = rawResult.summary || generateSummary(level, threatCategory, topSignal, rawResult.host);

    const studentProtection = rawResult.studentProtection && typeof rawResult.studentProtection === "object"
      ? rawResult.studentProtection
      : {
          isStudentTargeted: threatCategory.startsWith("student_") || threatCategory === "financial_aid_scam",
          detectedTargets: [],
          advice: [
            "Official university logins always use your institution's verified .edu domain.",
            "Campus IT will never email asking for your password or Duo/MFA codes."
          ]
        };

    return {
      ok: rawResult.ok !== false,
      version: SCHEMA_VERSION,
      timestamp: rawResult.timestamp || Date.now(),
      url: String(rawResult.url || rawResult.input || ""),
      host: String(rawResult.host || ""),
      score,
      level,
      isHighRisk: score >= 70,
      threatCategory,
      summary,
      signals,
      pageSignals: Array.isArray(rawResult.pageSignals) ? rawResult.pageSignals : [],
      studentProtection,
      error: rawResult.error || null
    };
  }

  const SharedSchema = {
    SCHEMA_VERSION,
    RISK_LEVELS,
    categorizeThreat,
    generateSummary,
    createSafeFallbackResult,
    formatResult
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = SharedSchema;
  } else {
    global.PhishLensSchema = SharedSchema;
  }
})(typeof window !== "undefined" ? window : globalThis);
