/**
 * NETRA — Background Service Worker (Manifest V3)
 * Manages per-tab badges, desktop security notifications, threat deduplication,
 * Gemini AI enrichment, and cached tab analysis results with full error boundaries.
 */

// Load Gemini AI analyzer module into service worker scope
try { importScripts("gemini-analyzer.js"); } catch (e) { console.warn("[NETRA] Gemini module unavailable:", e.message); }

const COLORS = {
  dangerous: "#dc2626",      // Red
  suspicious: "#ea580c",     // Orange
  caution: "#ca8a04",        // Yellow
  "likely safe": "#16a34a",  // Green
  unknown: "#64748b"         // Slate
};

// Threat notification deduplication cache:
// Key: `${tabId}:${normalizedUrl}:${threatCategory}` -> { timestamp, scoreTier }
const notifiedThreats = new Map();
const NOTIFICATION_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes

// Notification ID to tab metadata map for click-to-focus
const activeNotifications = new Map();

// Tab analysis cache: tabId -> PhishLensResult
const tabAnalysisCache = new Map();

/**
 * Normalizes URL for deduplication (drops query params and hashes to avoid notification spam on SPAs)
 */
function normalizeUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return `${u.protocol}//${u.hostname}${u.pathname}`;
  } catch (e) {
    return String(rawUrl || "");
  }
}

/**
 * Checks if a desktop notification should be sent, or suppressed to prevent spam
 */
function shouldNotify(tabId, url, threatCategory, score) {
  const normUrl = normalizeUrl(url);
  const key = `${tabId}:${normUrl}:${threatCategory}`;
  const now = Date.now();
  const currentTier = Math.floor(score / 10);

  if (notifiedThreats.has(key)) {
    const existing = notifiedThreats.get(key);
    // If within cooldown and score hasn't escalated to a higher tier, suppress notification
    if (now - existing.timestamp < NOTIFICATION_COOLDOWN_MS && currentTier <= existing.scoreTier) {
      return false;
    }
  }

  // Update deduplication record
  notifiedThreats.set(key, { timestamp: now, scoreTier: currentTier });
  return true;
}

/**
 * Dispatches a high-priority desktop notification for dangerous student threats
 */
function triggerDesktopNotification(tabId, result) {
  try {
    if (!chrome.notifications || !chrome.notifications.create) {
      return;
    }

    const host = result.host || "Unknown host";
    const score = result.score || 0;
    const threatCat = result.threatCategory || "credential_harvest";

    if (!shouldNotify(tabId, result.url, threatCat, score)) {
      return;
    }

    const notifId = `pl-shield-${tabId}-${Date.now()}`;
    const iconUrl = chrome.runtime.getURL("icons/icon128.png");

    let alertTitle = "🚨 Utkarsh Ki Fish Alert";
    if (result.threatCategory === "student_portal_spoof") {
      alertTitle = "🚨 Utkarsh Ki Fish: Fake Campus Portal!";
    } else if (result.threatCategory === "financial_aid_scam") {
      alertTitle = "🚨 Utkarsh Ki Fish: Financial Aid Scam!";
    }

    const message = `[Risk ${score}/100 - ${result.level.toUpperCase()}] ${result.summary || "Suspicious phishing threat detected."}`;
    const context = `Host: ${host} • Never input your Student ID or SSO passwords.`;

    chrome.notifications.create(
      notifId,
      {
        type: "basic",
        iconUrl: iconUrl,
        title: alertTitle,
        message: message,
        contextMessage: context,
        priority: 2,
        requireInteraction: true
      },
      (createdId) => {
        if (chrome.runtime.lastError) {
          console.warn("Desktop notification creation warning:", chrome.runtime.lastError.message);
          return;
        }
        activeNotifications.set(createdId || notifId, { tabId, url: result.url });
      }
    );
  } catch (err) {
    console.error("PhishLens notification error caught gracefully:", err);
  }
}

/**
 * Handles incoming risk score & scan reports from content scripts
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  try {
    if (!msg || typeof msg !== "object") return false;

    // Report from content script
    if (msg.type === "pl-score" && sender && sender.tab) {
      const tabId = sender.tab.id;
      const result = msg.result || msg;
      const score = Number(result.score) || 0;
      const level = result.level || "unknown";

      // Cache the local result immediately for instant popup display
      tabAnalysisCache.set(tabId, result);

      // 1. Update extension action badge with local score (instant)
      const badgeText = score >= 40 ? "!" : score > 0 ? String(score) : "";
      chrome.action.setBadgeText({ tabId, text: badgeText });
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: COLORS[level] || COLORS.unknown
      });
      chrome.action.setTitle({
        tabId,
        title: `NETRA: ${score}/100 — ${level.toUpperCase()}\n${result.summary || ""}`
      });

      // 2. High-risk notification trigger (score >= 70 or dangerous)
      if (score >= 70 || result.isHighRisk || level === "dangerous") {
        triggerDesktopNotification(tabId, result);
      }

      if (sendResponse) sendResponse({ ok: true, cached: true });

      // 3. Async Gemini AI enrichment — non-blocking, updates cache when done
      if (globalThis.NETRA_Gemini && result.url && result.url.startsWith("http")) {
        const pageText  = msg.pageText  || "";
        const localSigs = result.signals || [];

        NETRA_Gemini.callGemini(result.url, score, localSigs, pageText)
          .then((geminiResult) => {
            if (!geminiResult) return; // API failed gracefully — keep local result

            const enriched = NETRA_Gemini.mergeResults(result, geminiResult);
            tabAnalysisCache.set(tabId, enriched);

            const eScore = enriched.score;
            const eLevel = enriched.level;

            // Update badge with AI-merged score
            const eBadge = eScore >= 40 ? "!" : eScore > 0 ? String(eScore) : "";
            chrome.action.setBadgeText({ tabId, text: eBadge });
            chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[eLevel] || COLORS.unknown });
            chrome.action.setTitle({
              tabId,
              title: `NETRA AI: ${eScore}/100 — ${eLevel.toUpperCase()}\n[Gemini: ${geminiResult.verdict}]`
            });

            // Re-notify if AI bumped a page into dangerous territory
            if (eScore >= 70 && score < 70) {
              triggerDesktopNotification(tabId, enriched);
            }

            // Push enriched result to the popup (via runtime broadcast) and content script (banner)
            chrome.runtime.sendMessage({ type: "pl-gemini-update", result: enriched, tabId })
              .catch(() => {}); // Popup may be closed — ignore
            chrome.tabs.sendMessage(tabId, { type: "pl-gemini-update", result: enriched })
              .catch(() => {}); // Content script error — ignore
          })
          .catch((err) => console.warn("[NETRA-Gemini] enrichment error:", err.message));
      }

      return true;
    }

    // Popup requesting cached result for active tab
    if (msg.type === "pl-get-cached-result" && msg.tabId) {
      const cached = tabAnalysisCache.get(msg.tabId);
      if (sendResponse) sendResponse({ ok: !!cached, result: cached || null });
      return true;
    }
  } catch (err) {
    console.error("PhishLens background onMessage error caught gracefully:", err);
    if (sendResponse) sendResponse({ ok: false, error: err.message });
  }
  return true;
});

/**
 * Handle notification clicks: focus tab and bring to front
 */
if (chrome.notifications && chrome.notifications.onClicked) {
  chrome.notifications.onClicked.addListener((notifId) => {
    try {
      const data = activeNotifications.get(notifId);
      if (data && data.tabId) {
        chrome.tabs.get(data.tabId, (tab) => {
          if (chrome.runtime.lastError || !tab) return;
          chrome.tabs.update(data.tabId, { active: true });
          if (tab.windowId) {
            chrome.windows.update(tab.windowId, { focused: true });
          }
        });
      }
      chrome.notifications.clear(notifId);
      activeNotifications.delete(notifId);
    } catch (err) {
      console.warn("Error handling notification click:", err);
    }
  });
}

/**
 * Clean up tab state on navigation
 */
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  try {
    if (info.status === "loading") {
      chrome.action.setBadgeText({ tabId, text: "" });
      // If URL changed, clear cached result
      if (info.url) {
        tabAnalysisCache.delete(tabId);
      }
    }
  } catch (err) {
    console.warn("Error handling tab update:", err);
  }
});

/**
 * Clean up cache and deduplication entries when a tab is closed
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  try {
    tabAnalysisCache.delete(tabId);
    // Remove deduplication records for this tab
    for (const key of notifiedThreats.keys()) {
      if (key.startsWith(`${tabId}:`)) {
        notifiedThreats.delete(key);
      }
    }
    // Remove active notification references
    for (const [notifId, data] of activeNotifications.entries()) {
      if (data.tabId === tabId) {
        activeNotifications.delete(notifId);
      }
    }
  } catch (err) {
    console.warn("Error handling tab removal:", err);
  }
});
