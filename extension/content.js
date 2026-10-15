/**
 * PhishLens Student Shield — Content Script & Automatic In-Page Scanner
 * Performs local page analysis, dispatches standardized results to background worker,
 * and renders an isolated Shadow DOM warning banner with student-specific guidance.
 */
(function () {
  "use strict";

  if (window.__phishlensLoaded) return;
  window.__phishlensLoaded = true;

  const LEVEL_COLOR = {
    dangerous: "#dc2626",      // Crimson Red
    suspicious: "#ea580c",     // Orange
    caution: "#ca8a04",        // Amber
    "likely safe": "#16a34a"   // Emerald Green
  };

  let lastResult = null;
  let bannerHost = null;

  /**
   * Safely captures DOM signals without throwing exceptions
   */
  function snapshot() {
    try {
      const host = location.hostname.toLowerCase();
      const forms = Array.from(document.querySelectorAll("form")).map((f) => {
        try {
          return {
            action: f.getAttribute("action") || "",
            method: (f.getAttribute("method") || "get").toLowerCase(),
            hasPassword: !!f.querySelector('input[type="password"]'),
          };
        } catch (e) {
          return { action: "", method: "get", hasPassword: false };
        }
      });

      const inputs = Array.from(document.querySelectorAll("input,select,textarea"));
      const inputNames = inputs
        .flatMap((i) => [
          i.name,
          i.id,
          i.placeholder,
          i.getAttribute("aria-label"),
          i.getAttribute("autocomplete")
        ])
        .filter(Boolean);

      const iframes = Array.from(document.querySelectorAll("iframe"));
      const hiddenIframes = iframes.filter((f) => {
        try {
          const r = f.getBoundingClientRect();
          const s = getComputedStyle(f);
          return r.width < 5 || r.height < 5 || s.display === "none" || s.visibility === "hidden";
        } catch (e) {
          return false;
        }
      }).length;

      const anchors = Array.from(document.querySelectorAll("a[href]"));
      const externalLinks = anchors.filter((a) => {
        try {
          const h = new URL(a.href, location.href).hostname.toLowerCase();
          return h && h !== host && /^https?$/i.test(new URL(a.href, location.href).protocol);
        } catch (e) {
          return false;
        }
      }).length;

      let bodyText = "";
      try {
        bodyText = (document.body ? document.body.innerText : "").slice(0, 60000);
      } catch (e) {}

      return {
        url: location.href,
        passwordFields: document.querySelectorAll('input[type="password"]').length,
        forms,
        inputNames,
        hiddenIframes,
        externalLinks,
        totalLinks: anchors.length,
        text: bodyText,
      };
    } catch (err) {
      console.warn("PhishLens snapshot error caught:", err);
      return {
        url: location.href,
        passwordFields: 0,
        forms: [],
        inputNames: [],
        hiddenIframes: 0,
        externalLinks: 0,
        totalLinks: 0,
        text: ""
      };
    }
  }

  /**
   * Injects the isolated Shadow DOM Student Shield Warning Banner
   */
  function injectBanner(result) {
    try {
      if (bannerHost) {
        bannerHost.remove();
        bannerHost = null;
      }

      const color = LEVEL_COLOR[result.level] || "#dc2626";
      const hostEl = document.createElement("div");
      hostEl.id = "phishlens-student-shield-banner";
      hostEl.style.all = "initial";

      const shadow = hostEl.attachShadow({ mode: "open" });
      const topSignals = (result.signals || []).filter((s) => s.weight > 0).slice(0, 4);
      const studentAdvice = (result.studentProtection && result.studentProtection.advice) || [];
      const isDangerous = result.score >= 70;

      shadow.innerHTML = `
        <style>
          :host {
            all: initial;
            display: block;
          }
          .shield-banner {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 2147483647;
            background: linear-gradient(135deg, ${color} 0%, #1e1b4b 160%);
            color: #ffffff;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 13px;
            line-height: 1.45;
            padding: 12px 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.45);
            border-bottom: 2px solid rgba(255, 255, 255, 0.2);
            animation: slideDown 0.25s ease-out;
          }
          @keyframes slideDown {
            from { transform: translateY(-100%); }
            to { transform: translateY(0); }
          }
          .banner-container {
            max-width: 1180px;
            margin: 0 auto;
          }
          .header-row {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
          }
          .brand-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-weight: 800;
            font-size: 14px;
            letter-spacing: 0.3px;
            background: rgba(0, 0, 0, 0.3);
            padding: 4px 10px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.25);
          }
          .score-pill {
            font-weight: 800;
            font-size: 15px;
            background: rgba(255, 255, 255, 0.2);
            padding: 3px 8px;
            border-radius: 6px;
          }
          .level-pill {
            text-transform: uppercase;
            font-weight: 800;
            letter-spacing: 0.8px;
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
            background: rgba(0, 0, 0, 0.35);
            border: 1px solid rgba(255, 255, 255, 0.4);
          }
          .summary-text {
            flex: 1;
            font-weight: 600;
            min-width: 280px;
          }
          .actions {
            display: flex;
            align-items: center;
            gap: 8px;
          }
          .btn {
            background: rgba(255, 255, 255, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.4);
            color: #ffffff;
            border-radius: 6px;
            padding: 5px 12px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.15s ease;
          }
          .btn:hover {
            background: rgba(255, 255, 255, 0.35);
          }
          .btn-close {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 5px 10px;
          }
          .details-panel {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid rgba(255, 255, 255, 0.15);
            display: grid;
            grid-template-columns: 1.2fr 1fr;
            gap: 16px;
          }
          @media (max-width: 768px) {
            .details-panel { grid-template-columns: 1fr; }
          }
          .panel-title {
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
            opacity: 0.9;
          }
          ul {
            margin: 0;
            padding-left: 18px;
          }
          li {
            margin-bottom: 4px;
            font-size: 12px;
          }
          .advice-box {
            background: rgba(0, 0, 0, 0.25);
            border-radius: 6px;
            padding: 8px 12px;
            border-left: 3px solid #38bdf8;
          }
        </style>
        <div class="shield-banner">
          <div class="banner-container">
            <div class="header-row">
              <div class="brand-badge">
                <span>🛡️ Utkarsh Ki Fish</span>
                <span style="font-size:11px;opacity:0.85;">Shield</span>
              </div>
              <span class="score-pill">${result.score}/100</span>
              <span class="level-pill">${result.level}</span>
              <span class="summary-text">${result.summary}</span>
              <div class="actions">
                <button class="btn" id="pl-toggle-details">View Details</button>
                <button class="btn btn-close" id="pl-close" title="Dismiss banner">✕</button>
              </div>
            </div>
            <div class="details-panel" id="pl-panel" style="display: ${isDangerous ? 'grid' : 'none'};">
              <div>
                <div class="panel-title">Detected Threat Signals (${topSignals.length})</div>
                <ul>
                  ${topSignals.map((s) => `<li><b>${s.title}</b>: ${s.detail}</li>`).join("")}
                </ul>
              </div>
              <div class="advice-box">
                <div class="panel-title" style="color:#7dd3fc;">Student Safety Guidance</div>
                <ul>
                  ${studentAdvice.slice(0, 3).map((a) => `<li>${a}</li>`).join("")}
                </ul>
              </div>
            </div>
          </div>
        </div>
      `;

      shadow.getElementById("pl-close").onclick = () => {
        hostEl.remove();
        bannerHost = null;
        if (document.body) document.body.style.paddingTop = "0px";
      };

      const toggleBtn = shadow.getElementById("pl-toggle-details");
      const panel = shadow.getElementById("pl-panel");
      toggleBtn.onclick = () => {
        const isHidden = panel.style.display === "none";
        panel.style.display = isHidden ? "grid" : "none";
        toggleBtn.textContent = isHidden ? "Hide Details" : "View Details";
      };

      (document.documentElement || document.body).appendChild(hostEl);
      bannerHost = hostEl;

      // Ensure banner doesn't obscure the target page content
      if (document.body) {
        document.body.style.paddingTop = isDangerous ? "110px" : "60px";
      }
    } catch (err) {
      console.warn("PhishLens banner injection error caught:", err);
    }
  }

  /**
   * Main scan execution
   */
  function run() {
    try {
      if (!window.PhishLens || typeof window.PhishLens.analyze !== "function") {
        return;
      }

      const snap = snapshot();
      lastResult = window.PhishLens.analyze(location.href, snap);

      // Send result to background service worker (for badge and desktop notifications)
      try {
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            type: "pl-score",
            result: lastResult
          }, () => {
            if (chrome.runtime.lastError) {
              // Extension context might be disconnected during reloading; safe to ignore
            }
          });
        }
      } catch (e) {
        // Safe fail
      }

      // Automatically display in-page warning banner for suspicious or dangerous scores
      if (lastResult.score >= 40) {
        injectBanner(lastResult);
      } else if (bannerHost && lastResult.score < 40) {
        bannerHost.remove();
        bannerHost = null;
        if (document.body) document.body.style.paddingTop = "0px";
      }
    } catch (err) {
      console.error("PhishLens content script scan failed gracefully:", err);
    }
  }

  // Initial execution
  run();

  // Watch for dynamic DOM changes (SPAs, dynamic login modals) with debouncing
  let debounceTimer = null;
  try {
    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        run();
      }, 1200);
    });

    if (document.documentElement) {
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
    }
  } catch (err) {
    console.warn("PhishLens MutationObserver init failed gracefully:", err);
  }

  // Handle messages from popup
  try {
    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      try {
        if (!msg) return;
        if (msg.type === "pl-get-result") {
          sendResponse(lastResult);
        } else if (msg.type === "pl-rescan") {
          run();
          sendResponse(lastResult);
        }
      } catch (e) {
        sendResponse(null);
      }
      return true;
    });
  } catch (err) {
    console.warn("PhishLens content onMessage init failed:", err);
  }
})();
