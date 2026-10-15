/**
 * PhishLens Student Shield — Automated Verification Suite
 * Validates Manifest V3 compliance, engine heuristics, schema conformance,
 * deduplication logic, and error boundaries.
 */

const fs = require('fs');
const path = require('path');
const engine = require('../engine.js');
const schema = require('../shared-schema.js');

let totalTests = 0;
let passedTests = 0;

function assert(condition, testName) {
  totalTests++;
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passedTests++;
  } else {
    console.error(`  ✗ FAIL: ${testName}`);
  }
}

console.log("\n========================================================");
console.log("  PHISHLENS STUDENT SHIELD — VERIFICATION SUITE");
console.log("========================================================\n");

// 1. MANIFEST V3 VALIDATION
console.log("[1] Manifest V3 Compliance & Permissions Check");
const manifestPath = path.join(__dirname, '../extension/manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

assert(manifest.manifest_version === 3, "Manifest version is 3 (MV3)");
assert(manifest.permissions.includes("notifications"), "Has 'notifications' permission");
assert(manifest.permissions.includes("tabs"), "Has 'tabs' permission");
assert(manifest.permissions.includes("storage"), "Has 'storage' permission");
assert(manifest.host_permissions && manifest.host_permissions.includes("<all_urls>"), "Has host permissions for <all_urls>");
assert(manifest.background && manifest.background.service_worker === "background.js", "Service worker configured as background.js");
assert(manifest.content_scripts && manifest.content_scripts[0].js.includes("content.js"), "Content scripts include content.js");

// Check icon files
const icon16 = path.join(__dirname, '../extension/icons/icon16.png');
const icon128 = path.join(__dirname, '../extension/icons/icon128.png');
assert(fs.existsSync(icon16) && fs.existsSync(icon128), "Extension icon files exist");

// 2. DETECTION ENGINE HEURISTICS
console.log("\n[2] Student Shield Detection Heuristics");

// Test 2A: Fake .edu subdomain
const resEduSpoof = engine.analyze('https://harvard.edu.login-portal.net');
assert(resEduSpoof.score >= 70, `Fake .edu spoof flagged as high-risk (Score: ${resEduSpoof.score})`);
assert(resEduSpoof.isHighRisk === true, "isHighRisk flag is true");
assert(resEduSpoof.threatCategory === "student_portal_spoof", `Threat category is student_portal_spoof (got: ${resEduSpoof.threatCategory})`);
assert(resEduSpoof.signals.some(s => s.id === "student-edu-spoof"), "Identified 'student-edu-spoof' signal");
assert(resEduSpoof.studentProtection.isStudentTargeted === true, "studentProtection.isStudentTargeted is true");

// Test 2B: Student financial aid lure
const resAidScam = engine.analyze('https://student-loan-forgiveness-claim.org/bursary');
assert(resAidScam.score >= 40, `Student aid scam flagged (Score: ${resAidScam.score})`);
assert(resAidScam.threatCategory === "financial_aid_scam", `Threat category is financial_aid_scam (got: ${resAidScam.threatCategory})`);
assert(resAidScam.signals.some(s => s.id === "student-financial-aid"), "Identified 'student-financial-aid' signal");

// Test 2C: Full page snapshot analysis (student credentials + http action)
const snapPhish = {
  url: "https://campus-verify.student-portal.xyz/login",
  passwordFields: 1,
  forms: [{
    action: "http://external-harvest.org/steal",
    method: "post",
    hasPassword: true
  }],
  inputNames: ["student_id", "student_email", "password"],
  hiddenIframes: 0,
  externalLinks: 5,
  totalLinks: 6,
  text: "Final Notice: Your student account deactivation is scheduled within 24 hours unless you confirm enrollment immediately."
};
const resPagePhish = engine.analyze(snapPhish.url, snapPhish);
assert(resPagePhish.score >= 70, `Page snapshot flagged as dangerous (Score: ${resPagePhish.score})`);
assert(resPagePhish.signals.some(s => s.id === "form-http" || s.id === "form-xdomain"), "Flagged unencrypted or cross-domain form post");
assert(resPagePhish.signals.some(s => s.id === "student-portal-lookalike"), "Flagged student-portal-lookalike credentials harvest");
assert(resPagePhish.signals.some(s => s.id === "student-urgency"), "Flagged student urgency panic language");

// Test 2D: Genuine University Domain (False-Positive Resistance)
const resLegitUni = engine.analyze('https://my.harvard.edu');
assert(resLegitUni.score === 0 && resLegitUni.level === "likely safe", `Legitimate university recognized as safe (Score: ${resLegitUni.score})`);
assert(resLegitUni.isHighRisk === false, "Legitimate university is not high risk");

// Test 2E: Brand typosquat (paypa1.com)
const resPaypal = engine.analyze('https://paypa1-secure-login.com');
assert(resPaypal.score >= 60, `Brand typosquatting detected (Score: ${resPaypal.score})`);

// 3. SHARED RESULT FORMAT SCHEMA VALIDATION
console.log("\n[3] Shared Schema Conformance Validation");
const formatted = schema.formatResult(resPagePhish);
assert(formatted.version === "2.0.0-student-shield", "Version matches schema specification");
assert(typeof formatted.score === "number" && formatted.score >= 0 && formatted.score <= 100, "Score is numeric between 0 and 100");
assert(["dangerous", "suspicious", "caution", "likely safe", "unknown"].includes(formatted.level), "Level matches valid enum values");
assert(Array.isArray(formatted.signals), "Signals is an array");
assert(formatted.studentProtection && Array.isArray(formatted.studentProtection.advice), "Student protection advice list present");

// 4. DEDUPLICATION LOGIC SIMULATION
console.log("\n[4] Desktop Notification Deduplication Validation");
const notifiedThreats = new Map();
const NOTIFICATION_COOLDOWN_MS = 5 * 60 * 1000;

function simulateShouldNotify(tabId, url, threatCategory, score, currentTime) {
  const normUrl = url.split("?")[0].split("#")[0];
  const key = `${tabId}:${normUrl}:${threatCategory}`;
  const currentTier = Math.floor(score / 10);

  if (notifiedThreats.has(key)) {
    const existing = notifiedThreats.get(key);
    if (currentTime - existing.timestamp < NOTIFICATION_COOLDOWN_MS && currentTier <= existing.scoreTier) {
      return false; // Suppressed duplicate
    }
  }

  notifiedThreats.set(key, { timestamp: currentTime, scoreTier: currentTier });
  return true; // Send notification
}

const t0 = 1000000;
const notify1 = simulateShouldNotify(1, "https://fake-login.com/page", "credential_harvest", 85, t0);
assert(notify1 === true, "First encounter triggers desktop notification");

// Immediate duplicate from DOM mutation observer
const notify2 = simulateShouldNotify(1, "https://fake-login.com/page", "credential_harvest", 85, t0 + 1500);
assert(notify2 === false, "Duplicate trigger within cooldown is correctly suppressed");

// Different page on same tab
const notify3 = simulateShouldNotify(1, "https://fake-login.com/other-page", "credential_harvest", 85, t0 + 2000);
assert(notify3 === true, "New URL path triggers notification");

// Same page after cooldown expires (5 mins + 1 sec)
const notify4 = simulateShouldNotify(1, "https://fake-login.com/page", "credential_harvest", 85, t0 + (5 * 60 * 1000) + 1000);
assert(notify4 === true, "Notification allowed after cooldown expires");

// 5. RESILIENCE & ERROR BOUNDARIES
console.log("\n[5] Fail-Safe & Error Resilience Validation");
const nullAnalysis = engine.analyze(null);
assert(nullAnalysis.ok === false && nullAnalysis.score === 0, "Null input handled gracefully without throwing");

const invalidUrlAnalysis = engine.analyze("not a valid url!@#$%%^&*()");
assert(invalidUrlAnalysis.ok !== undefined, "Malformed string handled without crash");

const emptyPageAnalysis = engine.analyzePage(null);
assert(Array.isArray(emptyPageAnalysis) && emptyPageAnalysis.length === 0, "Null page snapshot returns empty array safely");

console.log("\n========================================================");
console.log(`  VERIFICATION RESULTS: ${passedTests} / ${totalTests} TESTS PASSED`);
console.log("========================================================\n");

if (passedTests === totalTests) {
  process.exit(0);
} else {
  process.exit(1);
}
