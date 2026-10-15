/**
 * NETRA — Network Eye for Threat Recognition & Analysis
 * Content Script & Automatic In-Page Scanner v3.0
 * Performs local page analysis, dispatches results to background worker,
 * and renders an isolated Shadow DOM NETRA warning banner.
 */
(function () {
  "use strict";

  if (window.__netraLoaded) return;
  window.__netraLoaded = true;

  const LEVEL_COLOR = {
    dangerous:     "#ff3b5c",
    suspicious:    "#ff7b00",
    caution:       "#f0a500",
    "likely safe": "#00e87a"
  };

  let lastResult = null;
  let bannerHost = null;
  let currentBannerScore = null;
  let currentBannerLevel = null;
  let emailBannerHost = null;
  let currentEmailScore = null;

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
      console.warn("NETRA snapshot error caught:", err);
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
   * Extracts active email message data from Gmail, Outlook Web, Yahoo Mail, or webmail testbeds
   */
  function extractActiveEmail() {
    try {
      const hostname = location.hostname.toLowerCase();

      // 1. GMAIL (mail.google.com)
      if (hostname.includes("mail.google.com")) {
        const messageBodies = Array.from(document.querySelectorAll("div.ii.gt, div.a3s.aiL, div[role='listitem'] div.a3s"));
        if (!messageBodies.length) return null;

        const visibleBodies = messageBodies.filter((el) => {
          try {
            const rect = el.getBoundingClientRect();
            return rect.height > 20 && el.offsetParent !== null;
          } catch (e) { return false; }
        });
        const activeBodyEl = visibleBodies[visibleBodies.length - 1] || messageBodies[messageBodies.length - 1];
        if (!activeBodyEl) return null;

        const container = activeBodyEl.closest("div[role='listitem']") || activeBodyEl.closest(".adn") || activeBodyEl.parentElement;

        let senderEmail = "";
        let senderName = "";
        const senderEl = (container && (container.querySelector("span.gD") || container.querySelector("[email]"))) ||
                         document.querySelector("span.gD") || document.querySelector("[email]");
        if (senderEl) {
          senderEmail = senderEl.getAttribute("email") || "";
          senderName = senderEl.getAttribute("name") || senderEl.textContent.trim();
        }
        if (!senderEmail) {
          const goEl = container ? container.querySelector("span.go") : document.querySelector("span.go");
          if (goEl) {
            const m = goEl.textContent.match(/<([^>]+)>/) || goEl.textContent.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
            if (m) senderEmail = m[1];
          }
        }

        const subjectEl = document.querySelector("h2.hP") || document.querySelector("[data-thread-perm-id]");
        const subject = subjectEl ? subjectEl.textContent.trim() : (document.title.replace(/\s*-\s*Gmail.*$/i, "").trim());

        const bodyText = (activeBodyEl.innerText || activeBodyEl.textContent || "").slice(0, 30000);
        const rawBody = (activeBodyEl.innerHTML || "").slice(0, 50000);
        const linkEls = Array.from(activeBodyEl.querySelectorAll("a[href]"));
        const links = linkEls.map((a) => a.href).filter((h) => /^https?:\/\//i.test(h));

        return {
          from: senderEmail,
          displayName: senderName,
          subject,
          body: bodyText,
          rawBody,
          links,
          containerEl: container || activeBodyEl,
          bodyEl: activeBodyEl
        };
      }

      // 2. OUTLOOK WEB / OFFICE 365 (outlook.live.com, outlook.office.com, outlook.office365.com)
      if (hostname.includes("outlook.live.com") || hostname.includes("outlook.office.com") || hostname.includes("outlook.office365.com")) {
        const bodyEl = document.querySelector("div[aria-label='Message body'], div#UniqueMessageBody, div.rps_");
        if (!bodyEl) return null;

        let senderEmail = "";
        let senderName = "";
        const persona = document.querySelector("div[data-testid='sender_persona'], .ms-Persona-primaryText, div[role='heading'] span");
        if (persona) senderName = persona.textContent.trim();
        const emailSpan = document.querySelector("span[title*='@'], [data-hovercard-id*='@']");
        if (emailSpan) {
          const title = emailSpan.getAttribute("title") || emailSpan.textContent;
          const m = title.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
          if (m) senderEmail = m[1];
        }

        const subjectEl = document.querySelector("div[role='heading'][aria-level='1'], .allowTextSelection[role='heading']");
        const subject = subjectEl ? subjectEl.textContent.trim() : document.title;
        const bodyText = (bodyEl.innerText || "").slice(0, 30000);
        const rawBody = (bodyEl.innerHTML || "").slice(0, 50000);
        const linkEls = Array.from(bodyEl.querySelectorAll("a[href]"));
        const links = linkEls.map((a) => a.href).filter((h) => /^https?:\/\//i.test(h));

        return {
          from: senderEmail,
          displayName: senderName,
          subject,
          body: bodyText,
          rawBody,
          links,
          containerEl: bodyEl.closest("[role='main']") || bodyEl.parentElement,
          bodyEl
        };
      }

      // 3. YAHOO MAIL (mail.yahoo.com)
      if (hostname.includes("mail.yahoo.com")) {
        const bodyEl = document.querySelector("div[data-test-id='message-body']");
        if (!bodyEl) return null;
        const fromEl = document.querySelector("span[data-test-id='message-from'], .msg-from");
        const sender = fromEl ? fromEl.textContent.trim() : "";
        const subjectEl = document.querySelector("span[data-test-id='message-group-subject-text']");
        const subject = subjectEl ? subjectEl.textContent.trim() : document.title;
        const bodyText = (bodyEl.innerText || "").slice(0, 30000);
        const rawBody = (bodyEl.innerHTML || "").slice(0, 50000);
        const linkEls = Array.from(bodyEl.querySelectorAll("a[href]"));
        const links = linkEls.map((a) => a.href).filter((h) => /^https?:\/\//i.test(h));

        return {
          from: sender,
          displayName: sender,
          subject,
          body: bodyText,
          rawBody,
          links,
          containerEl: bodyEl.parentElement,
          bodyEl
        };
      }

      // 4. GENERIC / DEMO / CAMPUS WEBMAIL TESTBED
      // Detects simulated webmail clients or university email portals
      const genericContainer = document.querySelector("[data-netra-email], .email-view, .email-container, .mail-message, #email-view, article.email-card, .simulated-email");
      if (genericContainer) {
        const fromEl = genericContainer.querySelector("[data-sender], .email-from, .mail-from, .from-field");
        const subEl = genericContainer.querySelector("[data-subject], .email-subject, .mail-subject, .subject-field");
        const bEl = genericContainer.querySelector("[data-body], .email-body, .mail-body, .message-content") || genericContainer;

        let fromStr = fromEl ? (fromEl.getAttribute("data-sender") || fromEl.textContent.trim()) : "";
        let dispName = "";
        const m = fromStr.match(/^(.*?)\s*<([^>]+)>/);
        if (m) {
          dispName = m[1].replace(/["']/g, "").trim();
          fromStr = m[2].trim();
        }
        const subject = subEl ? subEl.textContent.trim() : "";
        const bodyText = (bEl.innerText || "").slice(0, 30000);
        const rawBody = (bEl.innerHTML || "").slice(0, 50000);
        const linkEls = Array.from(bEl.querySelectorAll("a[href]"));
        const links = linkEls.map((a) => a.href).filter((h) => /^https?:\/\//i.test(h));

        return {
          from: fromStr,
          displayName: dispName,
          subject,
          body: bodyText,
          rawBody,
          links,
          containerEl: genericContainer,
          bodyEl: bEl
        };
      }

      return null;
    } catch (e) {
      console.warn("NETRA: extractActiveEmail caught error:", e);
      return null;
    }
  }

  /**
   * Visually highlights suspicious links inside the opened email body
   */
  function highlightSuspiciousLinks(bodyEl, suspiciousLinks) {
    if (!bodyEl || !suspiciousLinks || !suspiciousLinks.length) return;
    try {
      const anchors = Array.from(bodyEl.querySelectorAll("a[href]"));
      anchors.forEach((a) => {
        const href = (a.href || "").toLowerCase();
        const matches = suspiciousLinks.find((s) => {
          if (!s || !s.url) return false;
          const surl = s.url.toLowerCase();
          try {
            return href === surl || href.startsWith(surl) || href.includes(new URL(s.url).hostname.toLowerCase());
          } catch (e) {
            return href.includes(surl);
          }
        });

        if (matches) {
          a.style.outline = "2px dashed #f43f5e";
          a.style.backgroundColor = "rgba(244,63,94,0.18)";
          a.style.borderRadius = "4px";
          a.style.padding = "1px 5px";
          a.style.transition = "all 0.2s";
          a.title = `[NETRA Shield Warning: Phishing Link Risk ${matches.score}/100 - Do Not Click!]`;

          if (!a.dataset.netraFlagged) {
            a.dataset.netraFlagged = "true";
            const badge = document.createElement("span");
            badge.className = "netra-phish-badge";
            badge.textContent = ` ⚠️ [Phishing Link · Risk ${matches.score}]`;
            badge.style.cssText = "color:#f43f5e;font-size:10px;font-weight:800;font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin-left:4px;vertical-align:middle;display:inline-block;pointer-events:none;background:rgba(244,63,94,0.12);border:1px solid rgba(244,63,94,0.3);padding:1px 5px;border-radius:4px;";
            a.insertAdjacentElement("afterend", badge);
          }
        }
      });
    } catch (e) {
      console.warn("NETRA: highlightSuspiciousLinks caught:", e);
    }
  }

  /**
   * Injects an in-line warning banner directly inside the opened email
   */
  function injectEmailBanner(result, emailData) {
    try {
      if (emailBannerHost && currentEmailScore === result.score) {
        return;
      }

      if (emailBannerHost) {
        emailBannerHost.remove();
        emailBannerHost = null;
      }

      currentEmailScore = result.score;
      const isDangerous = result.score >= 70;
      const color = isDangerous ? "#f43f5e" : "#f97316";

      const hostEl = document.createElement("div");
      hostEl.id = "netra-email-phish-alert";
      hostEl.style.all = "initial";
      hostEl.style.display = "block";
      hostEl.style.margin = "10px 0 16px 0";

      const shadow = hostEl.attachShadow({ mode: "open" });
      const topSignals = (result.signals || []).filter((s) => s.weight > 0).slice(0, 5);
      const advice = (result.studentProtection && result.studentProtection.advice) || [];
      const suspLinks = result.suspiciousLinks || [];

      shadow.innerHTML = `
        <style>
          :host { all: initial; display: block; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
          .email-alert-box {
            background: linear-gradient(135deg, #1c0e18 0%, #111827 100%);
            border: 1.5px solid ${color};
            border-left: 6px solid ${color};
            border-radius: 10px;
            padding: 14px 18px;
            color: #f1f5f9;
            box-shadow: 0 6px 24px rgba(244,63,94,0.22);
            animation: fadeIn 0.25s ease-out;
            font-size: 13px;
            line-height: 1.45;
          }
          @keyframes fadeIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: none; } }
          .header-row {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 8px;
          }
          .alert-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            font-weight: 800;
            font-size: 12px;
            letter-spacing: 0.5px;
            background: ${color}22;
            color: ${color};
            border: 1px solid ${color}66;
            border-radius: 6px;
            padding: 3px 8px;
          }
          .score-badge {
            font-weight: 800;
            font-size: 12px;
            background: ${color};
            color: #ffffff;
            border-radius: 12px;
            padding: 2px 9px;
          }
          .btn-dismiss {
            margin-left: auto;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #94a3b8;
            border-radius: 6px;
            padding: 3px 9px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.15s;
          }
          .btn-dismiss:hover { background: rgba(255, 255, 255, 0.2); color: #fff; }
          .summary-title {
            font-size: 13.5px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 5px;
          }
          .sender-info {
            font-size: 12px;
            color: #cbd5e1;
            margin-bottom: 10px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 6px;
            padding: 6px 10px;
          }
          .sender-code {
            color: #f43f5e;
            font-family: monospace;
            font-weight: 700;
          }
          .chips-row {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: 10px;
          }
          .chip {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 11px;
            font-weight: 600;
            background: rgba(244,63,94,0.12);
            border: 1px solid rgba(244,63,94,0.3);
            color: #fca5a5;
            padding: 2px 8px;
            border-radius: 14px;
          }
          .links-warning {
            background: rgba(244,63,94,0.08);
            border: 1px solid rgba(244,63,94,0.25);
            border-radius: 6px;
            padding: 8px 10px;
            margin-bottom: 10px;
            font-size: 11.5px;
          }
          .links-title { font-weight: 700; color: #f87171; margin-bottom: 4px; }
          .advice-box {
            background: rgba(0, 0, 0, 0.35);
            border-left: 3px solid #f59e0b;
            border-radius: 4px;
            padding: 7px 11px;
            font-size: 11.5px;
            color: #e2e8f0;
          }
        </style>
        <div class="email-alert-box">
          <div class="header-row">
            <span class="alert-badge">🚨 PHISHING EMAIL DETECTED</span>
            <span class="score-badge">RISK: ${result.score}/100</span>
            <button class="btn-dismiss" id="netra-dismiss-email-banner">✕ Dismiss Warning</button>
          </div>
          <div class="summary-title">${result.summary}</div>
          <div class="sender-info">
            <b>Sender Verification:</b> Claims to be <i>"${result.displayName || "Unknown"}"</i> but sender address is <span class="sender-code">${result.from || "hidden / undisclosed"}</span>
          </div>
          <div class="chips-row">
            ${topSignals.map((s) => `<span class="chip">⚠️ ${s.title}</span>`).join("")}
          </div>
          ${suspLinks.length ? `
            <div class="links-warning">
              <div class="links-title">🛑 Flagged Malicious Links in Email:</div>
              <ul style="margin:0;padding-left:16px;">
                ${suspLinks.slice(0, 3).map((l) => `<li><span class="sender-code">${l.url}</span> (Risk ${l.score}/100) — ${l.summary}</li>`).join("")}
              </ul>
            </div>
          ` : ""}
          <div class="advice-box">
            <b>🛡️ Student Security Guidance:</b> ${advice[0] || "Never click links or open attachments in unverified emails. Contact your university IT helpdesk."}
          </div>
        </div>
      `;

      shadow.getElementById("netra-dismiss-email-banner").onclick = () => {
        hostEl.remove();
        emailBannerHost = null;
        currentEmailScore = null;
      };

      // Anchor banner directly above the email body, or prepend to container
      if (emailData.bodyEl && emailData.bodyEl.parentElement) {
        emailData.bodyEl.parentElement.insertBefore(hostEl, emailData.bodyEl);
      } else if (emailData.containerEl) {
        emailData.containerEl.prepend(hostEl);
      } else {
        document.body.prepend(hostEl);
      }
      emailBannerHost = hostEl;
    } catch (err) {
      console.warn("NETRA: email banner injection error caught:", err);
    }
  }

  /**
   * Injects the isolated Shadow DOM Student Shield Warning Banner
   */
  function injectBanner(result) {
    try {
      if (bannerHost && currentBannerScore === result.score && currentBannerLevel === result.level) {
        return;
      }

      if (bannerHost) {
        bannerHost.remove();
        bannerHost = null;
      }

      currentBannerScore = result.score;
      currentBannerLevel = result.level;

      const color = LEVEL_COLOR[result.level] || "#dc2626";
      const hostEl = document.createElement("div");
      hostEl.id = "netra-threat-eye-banner";
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
                <span>👁️ NETRA</span>
                <span style="font-size:11px;opacity:0.85;">Shield</span>
              </div>
              <span class="score-pill">${result.score}/100</span>
              <span class="level-pill">${result.level}</span>
              <span class="summary-text">${result.summary}</span>
              <div class="actions">
                <button class="btn" id="netra-toggle-details">View Details</button>
                <button class="btn btn-close" id="netra-close" title="Dismiss banner">✕</button>
              </div>
            </div>
            <div class="details-panel" id="netra-panel" style="display: ${isDangerous ? 'grid' : 'none'};">
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

      shadow.getElementById("netra-close").onclick = () => {
        hostEl.remove();
        bannerHost = null;
        currentBannerScore = null;
        currentBannerLevel = null;
        if (document.body) document.body.style.paddingTop = "0px";
      };

      const toggleBtn = shadow.getElementById("netra-toggle-details");
      const panel = shadow.getElementById("netra-panel");
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
      console.warn("NETRA banner injection error caught:", err);
    }
  }

  /**
   * Main scan execution — checks active webmail emails first, falls back to page scanner
   */
  function run() {
    try {
      if (!window.NETRA || typeof window.NETRA.analyze !== "function") {
        return;
      }

      // Check if an email message is currently open in Gmail / Outlook / Yahoo / webmail testbed
      const activeEmail = extractActiveEmail();
      if (activeEmail && typeof window.NETRA.analyzeEmail === "function") {
        const emailResult = window.NETRA.analyzeEmail(activeEmail);
        lastResult = emailResult;

        // Send email result to background service worker (for badge, notifications, popup)
        try {
          if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({
              type: "netra-score",
              result: emailResult,
              pageText: activeEmail.body ? activeEmail.body.slice(0, 1200) : ""
            }, () => {
              if (chrome.runtime.lastError) {}
            });
          }
        } catch (e) {}

        // If suspicious or dangerous email, display in-email warning banner & highlight links
        if (emailResult.score >= 40) {
          injectEmailBanner(emailResult, activeEmail);
          highlightSuspiciousLinks(activeEmail.bodyEl, emailResult.suspiciousLinks || []);
          if (emailResult.score >= 70) {
            injectBanner(emailResult);
          }
        } else {
          if (emailBannerHost) {
            emailBannerHost.remove();
            emailBannerHost = null;
            currentEmailScore = null;
          }
          if (bannerHost) {
            bannerHost.remove();
            bannerHost = null;
            currentBannerScore = null;
            currentBannerLevel = null;
            if (document.body) document.body.style.paddingTop = "0px";
          }
        }
        return;
      }

      // If no email is active, clean up any previous email banner
      if (emailBannerHost) {
        emailBannerHost.remove();
        emailBannerHost = null;
        currentEmailScore = null;
      }

      // Standard page snapshot analysis
      const snap = snapshot();
      lastResult = window.NETRA.analyze(location.href, snap);

      // Send result + page text to background service worker (for badge, notifications, Gemini AI)
      try {
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            type: "netra-score",
            result: lastResult,
            pageText: snap.text ? snap.text.slice(0, 1200) : ""
          }, () => {
            if (chrome.runtime.lastError) {}
          });
        }
      } catch (e) {}

      // Automatically display in-page warning banner for suspicious or dangerous scores
      if (lastResult.score >= 40) {
        injectBanner(lastResult);
      } else if (bannerHost && lastResult.score < 40) {
        bannerHost.remove();
        bannerHost = null;
        currentBannerScore = null;
        currentBannerLevel = null;
        if (document.body) document.body.style.paddingTop = "0px";
      }
    } catch (err) {
      console.error("NETRA content script scan failed gracefully:", err);
    }
  }

  // Initial execution
  run();

  // Watch for dynamic DOM changes (email open, SPAs, dynamic login modals) with debouncing
  let debounceTimer = null;
  try {
    const observer = new MutationObserver((mutations) => {
      // Ignore mutations originating strictly within our own banners or badge elements
      let onlyBannerMutations = true;
      for (let i = 0; i < mutations.length; i++) {
        const t = mutations[i].target;
        if (!t) continue;
        if (
          t.id === "netra-threat-eye-banner" ||
          t.id === "netra-email-phish-alert" ||
          (t.classList && t.classList.contains("netra-phish-badge")) ||
          (t.closest && (t.closest("#netra-threat-eye-banner") || t.closest("#netra-email-phish-alert")))
        ) {
          continue;
        }
        onlyBannerMutations = false;
        break;
      }
      if (onlyBannerMutations) return;

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        run();
      }, 350);
    });

    if (document.documentElement) {
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
    }
  } catch (err) {
    console.warn("NETRA MutationObserver init failed gracefully:", err);
  }

  // Handle messages from popup
  try {
    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      try {
        if (!msg) return;
        if (msg.type === "netra-get-result" || msg.type === "pl-get-result") {
          sendResponse(lastResult);
        } else if (msg.type === "netra-rescan" || msg.type === "pl-rescan") {
          run();
          sendResponse(lastResult);
        } else if (msg.type === "netra-gemini-update" || msg.type === "pl-gemini-update") {
          // Background pushed an AI-enriched result — update local state and banner
          lastResult = msg.result;
          if (lastResult && lastResult.score >= 40) {
            injectBanner(lastResult);
          }
          sendResponse({ ok: true });
        }
      } catch (e) {
        sendResponse(null);
      }
      return true;
    });
  } catch (err) {
    console.warn("NETRA content onMessage init failed:", err);
  }
})();
