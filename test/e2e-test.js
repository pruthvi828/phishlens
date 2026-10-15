/**
 * NETRA Shield — Automated Verification Suite
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
console.log("  NETRA THREAT EYE — VERIFICATION SUITE");
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

// Test 2F: Google Phishing Quiz URL Qualification (False-Positive Exemption & Awareness Recognition)
const resGoogleQuiz = engine.analyze('https://phishingquiz.withgoogle.com/');
assert(resGoogleQuiz.score < 15 && resGoogleQuiz.level === "likely safe", `Google Phishing Quiz URL qualifies as safe (Score: ${resGoogleQuiz.score})`);
assert(resGoogleQuiz.isHighRisk === false, "Google Phishing Quiz is not high risk");
assert(resGoogleQuiz.signals.some(s => s.id === "security-education"), "Recognized verified cybersecurity training quiz platform");
assert(resGoogleQuiz.signals.some(s => s.id === "brand-official"), "Recognized official Google brand domain");

// Test 2G: Google Phishing Quiz Full Page DOM Snapshot Qualification
const snapGoogleQuiz = {
  url: "https://phishingquiz.withgoogle.com/",
  passwordFields: 1,
  forms: [{
    action: "",
    method: "post",
    hasPassword: true
  }],
  inputNames: ["name", "email", "password"],
  hiddenIframes: 0,
  externalLinks: 2,
  totalLinks: 8,
  text: "Question 2 of 8: You receive an email claiming unusual activity on your Google Account. Verify your password within 24 hours to prevent account deactivation. Is it Phishing or Legitimate?"
};
const resGoogleQuizPage = engine.analyze(snapGoogleQuiz.url, snapGoogleQuiz);
assert(resGoogleQuizPage.score < 15 && resGoogleQuizPage.level === "likely safe", `Google Phishing Quiz entire page qualifies as safe (Score: ${resGoogleQuizPage.score})`);
assert(resGoogleQuizPage.isHighRisk === false, "Google Phishing Quiz entire page is not high risk");
// Test 2H: Top Popular Brands Guaranteed Safe Score 0 (Amazon, YouTube, Facebook, Reddit, Wikipedia)
const topSafeBrands = [
  'https://www.amazon.com',
  'https://www.amazon.in',
  'https://www.amazon.co.uk',
  'https://www.youtube.com',
  'https://youtu.be/dQw4w9WgXcQ',
  'https://www.facebook.com',
  'https://m.facebook.com',
  'https://www.reddit.com',
  'https://en.wikipedia.org'
];
for (const brandUrl of topSafeBrands) {
  const resBrand = engine.analyze(brandUrl);
  assert(resBrand.score === 0 && resBrand.level === "likely safe", `Brand ${brandUrl} guaranteed safe (Score: ${resBrand.score}, got ${resBrand.level})`);
  assert(resBrand.isHighRisk === false, `Brand ${brandUrl} is not high risk`);
}

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

// 5. EMAIL PHISHING ANALYSIS VALIDATION
console.log("\n[5] Email Phishing Analysis Engine Validation");

const phishEmail = {
  from: "support-bursar@university-aid-verify.top",
  displayName: "University Financial Aid Office",
  subject: "URGENT: Student Account Suspension & Tuition Hold",
  body: "Dear student, your university account will be suspended within 24 hours due to unverified billing details. Verify your account immediately: http://portal.university-sso.top/login",
  rawBody: '<a href="http://portal.university-sso.top/login">http://university.edu/verify</a>',
  links: ["http://portal.university-sso.top/login"],
  attachments: ["financial_aid_invoice.exe"]
};

const emailRes = engine.analyzeEmail(phishEmail);
assert(emailRes.ok === true, "Email analysis completed successfully");
assert(emailRes.score >= 70, `Phishing email flagged as high risk (Score: ${emailRes.score})`);
assert(emailRes.isHighRisk === true, "isHighRisk is true for dangerous email");
assert(emailRes.studentProtection && emailRes.studentProtection.isStudentTargeted === true, "Identified student-targeted email attack");
assert(emailRes.signals.some(s => s.id === "email-dangerous-attach"), "Detected dangerous executable attachment");
assert(emailRes.signals.some(s => s.id === "email-student-urgency"), "Detected student urgency/account suspension phrase");

const legitEmail = {
  from: "admissions@stanford.edu",
  displayName: "Stanford Admissions",
  subject: "Welcome to Fall Quarter Registration",
  body: "Classes begin next week. Visit the official student registrar portal at https://stanford.edu for course schedules.",
  links: ["https://stanford.edu"],
  attachments: ["schedule.pdf"]
};

const legitRes = engine.analyzeEmail(legitEmail);
assert(legitRes.score < 20, `Legitimate university email recognized as safe (Score: ${legitRes.score})`);
assert(legitRes.isHighRisk === false, "Legitimate email is not high risk");

// 6. RESILIENCE & ERROR BOUNDARIES
console.log("\n[6] Fail-Safe & Error Resilience Validation");
const nullAnalysis = engine.analyze(null);
assert(nullAnalysis.ok === false && nullAnalysis.score === 0, "Null input handled gracefully without throwing");

const invalidUrlAnalysis = engine.analyze("not a valid url!@#$%%^&*()");
assert(invalidUrlAnalysis.ok !== undefined, "Malformed string handled without crash");

const emptyPageAnalysis = engine.analyzePage(null);
assert(Array.isArray(emptyPageAnalysis) && emptyPageAnalysis.length === 0, "Null page snapshot returns empty array safely");

const nullEmailAnalysis = engine.analyzeEmail(null);
assert(nullEmailAnalysis.ok === false && nullEmailAnalysis.score === 0, "Null email input handled gracefully");

console.log("\n========================================================");
console.log(`  VERIFICATION RESULTS: ${passedTests} / ${totalTests} TESTS PASSED`);
console.log("========================================================\n");

if (passedTests === totalTests) {
  process.exit(0);
} else {
  process.exit(1);
}
