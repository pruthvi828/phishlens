/**
 * NETRA — Network Eye for Threat Recognition & Analysis
 * Popup Interface Logic v4.0 — Sentinel Design
 * Privacy-first: AI is opt-in, stored preference persists via chrome.storage.local
 */

/* ─── Constants ─── */
const LEVEL_COLOR = {
  dangerous:     "var(--danger-c)",
  suspicious:    "var(--warn-c)",
  caution:       "var(--caution-c)",
  "likely safe": "var(--safe-c)",
  unknown:       "var(--unk-c)"
};

const LEVEL_CSS = {
  dangerous:     "#f43f5e",
  suspicious:    "#f97316",
  caution:       "#f59e0b",
  "likely safe": "#10b981",
  unknown:       "#64748b"
};

const LEVEL_ICON = {
  dangerous:     "🔴",
  suspicious:    "🟠",
  caution:       "🟡",
  "likely safe": "🟢",
  unknown:       "⚪"
};

const SIG_ICON = {
  high: "⚠️",
  med:  "🔶",
  low:  "🔸",
  good: "✅"
};

/* ─── AI Toggle State ─── */
let aiEnabled = true;

function loadAIPreference() {
  try {
    chrome.storage.local.get(["netra_ai_enabled"], (res) => {
      aiEnabled = res.netra_ai_enabled !== false; // default ON
      renderAIToggle();
      updatePrivacyRow();
    });
  } catch (e) {
    aiEnabled = true;
    renderAIToggle();
  }
}

function saveAIPreference(val) {
  try {
    chrome.storage.local.set({ netra_ai_enabled: val });
  } catch (e) {}
}

function renderAIToggle() {
  const wrap = document.getElementById("ai-toggle");
  if (!wrap) return;
  if (aiEnabled) {
    wrap.classList.add("active");
  } else {
    wrap.classList.remove("active");
  }
}

function updatePrivacyRow() {
  const dot  = document.getElementById("privacy-dot");
  const text = document.getElementById("privacy-text");
  const lbl  = document.getElementById("privacy-label");
  if (!dot || !text || !lbl) return;

  if (aiEnabled) {
    dot.classList.add("ai-active");
    text.textContent = "Local heuristics + Gemini AI — URL sent to Google API";
    lbl.textContent  = "AI ON";
    lbl.className    = "privacy-mode-label ai";
  } else {
    dot.classList.remove("ai-active");
    text.textContent = "Local heuristics only — no data leaves your device";
    lbl.textContent  = "PRIVATE";
    lbl.className    = "privacy-mode-label";
  }
}

document.getElementById("ai-toggle").addEventListener("click", () => {
  aiEnabled = !aiEnabled;
  saveAIPreference(aiEnabled);
  renderAIToggle();
  updatePrivacyRow();
  // Notify background about new AI preference
  try {
    chrome.runtime.sendMessage({ type: "netra-set-ai-enabled", enabled: aiEnabled });
  } catch (e) {}
});

/* ─── Score Orb (conic-gradient) ─── */
function setOrb(score, colorHex) {
  const orb = document.getElementById("score-orb");
  const num  = document.getElementById("score-num");
  if (!orb) return;
  const pct = Math.round(score) + "%";
  orb.style.setProperty("--orb-pct", pct);
  orb.style.setProperty("--orb-color", colorHex);
  if (num) {
    num.style.color = colorHex;
    num.textContent = typeof score === "number" ? String(Math.round(score)) : "0";
  }
}

/* ─── Render Gemini AI Panel ─── */
function renderAIPanel(result) {
  const panel     = document.getElementById("ai-panel");
  const shimmer   = document.getElementById("ai-shimmer");
  const content   = document.getElementById("ai-content");
  const badge     = document.getElementById("ai-badge");
  const confEl    = document.getElementById("ai-confidence");
  const reasoning = document.getElementById("ai-reasoning");
  const chips     = document.getElementById("ai-indicators");

  if (!panel) return;

  const isHttp = result && result.url && result.url.startsWith("http");

  if (!aiEnabled) {
    panel.classList.remove("visible");
    return;
  }

  if (result && result.geminiResult) {
    panel.classList.add("visible");
    if (shimmer) shimmer.style.display = "none";
    if (content) content.style.display = "block";

    const g = result.geminiResult;
    const vClass = (g.verdict || "").toLowerCase();
    if (badge) {
      badge.textContent = `${g.verdict} · ${g.geminiScore}/100`;
      badge.className   = `ai-verdict-badge ${
        vClass === "phishing"   ? "phishing"   :
        vClass === "safe"       ? "safe"        : "suspicious"}`;
    }
    if (confEl)    confEl.textContent    = g.confidence ? `${g.confidence} confidence` : "";
    if (reasoning) reasoning.textContent = g.reasoning  || "";
    if (chips) {
      chips.innerHTML = "";
      (g.topIndicators || []).forEach(t => {
        const s = document.createElement("span");
        s.className   = "ai-chip";
        s.textContent = t;
        chips.appendChild(s);
      });
    }
  } else if (isHttp) {
    // Waiting for background Gemini response
    panel.classList.add("visible");
    if (shimmer) shimmer.style.display = "flex";
    if (content) content.style.display = "none";
  } else {
    panel.classList.remove("visible");
  }
}

/* ─── Render Chip-style Signals ─── */
function renderSignals(signals) {
  const container = document.getElementById("sigs");
  const countEl   = document.getElementById("sig-count");
  if (!container) return;

  container.innerHTML = "";

  const meaningful = (signals || []).filter(s => s.id !== "gemini-ai");
  if (countEl) countEl.textContent = meaningful.length > 0 ? `${meaningful.length} signals` : "";

  if (meaningful.length === 0) {
    const chip = document.createElement("div");
    chip.className = "sig-chip good";
    chip.innerHTML = `<span class="sig-chip-icon">✅</span><span class="sig-chip-text">No threats detected</span>`;
    container.appendChild(chip);
    return;
  }

  for (const s of meaningful.slice(0, 8)) {
    const chip = document.createElement("div");
    chip.className = `sig-chip ${s.severity || "med"}`;
    chip.innerHTML = `
      <span class="sig-chip-icon">${SIG_ICON[s.severity] || "🔶"}</span>
      <span class="sig-chip-text">${s.title}</span>
      <div class="sig-tip">${s.detail || ""}</div>
    `;
    container.appendChild(chip);
  }
}

/* ─── Main Paint ─── */
function paintResult(result) {
  const card    = document.getElementById("verdict-card");
  const lvlEl   = document.getElementById("lvl");
  const hostEl  = document.getElementById("host");
  const sumEl   = document.getElementById("summary");
  const stuBox  = document.getElementById("student-box");
  const stuAdv  = document.getElementById("student-advice");

  if (card) card.classList.remove("scanning");

  if (!result || !result.ok) {
    setOrb(0, "#64748b");
    if (lvlEl) {
      lvlEl.textContent = "⊘ Restricted";
      lvlEl.style.cssText = "color:#64748b;border-color:#64748b;background:transparent;";
    }
    if (hostEl) hostEl.textContent = (result && result.host) ? result.host : "Internal page";
    if (sumEl)  sumEl.textContent  = "Browser internal pages cannot be scanned.";
    if (stuBox) stuBox.style.display = "none";
    renderSignals([{ severity:"good", title:"Isolated Context", detail:"Internal pages are isolated and safe." }]);
    renderAIPanel(null);
    return;
  }

  const hex = LEVEL_CSS[result.level] || "#64748b";
  setOrb(result.score, hex);

  if (lvlEl) {
    lvlEl.textContent = `${LEVEL_ICON[result.level] || "⚪"} ${result.level}`.toUpperCase();
    lvlEl.style.cssText = `color:${hex};border-color:${hex}44;background:${hex}11;`;
  }

  if (result.type === "email") {
    if (hostEl) {
      const senderText = result.displayName
        ? `${result.displayName} <${result.from}>`
        : (result.from || result.subject || "Opened Email");
      hostEl.innerHTML = `<span style="background:rgba(139,92,246,0.22);color:var(--violet);padding:1px 6px;border-radius:4px;font-size:9px;font-weight:800;letter-spacing:0.5px;margin-right:5px;">EMAIL</span><span style="font-size:10px;font-family:var(--mono);">${senderText}</span>`;
    }
  } else {
    if (hostEl) hostEl.textContent = result.host || result.url || "";
  }
  if (sumEl)  sumEl.textContent  = result.summary || "";

  // Student alert
  if (result.studentProtection && result.studentProtection.isStudentTargeted) {
    if (stuBox) stuBox.style.display = "block";
    const targets = (result.studentProtection.detectedTargets || []).join(", ") || "Campus / University Services";
    const advice  = (result.studentProtection.advice && result.studentProtection.advice[0]) || "Do not enter credentials here.";
    if (stuAdv) stuAdv.innerHTML = `<div style="font-size:10px;color:#94a3b8;margin-bottom:2px;">Target: ${targets}</div>${advice}`;
  } else {
    if (stuBox) stuBox.style.display = "none";
  }

  renderAIPanel(result);
  renderSignals(result.signals || []);
}

/* ─── Render URL Inspector Result (compact card) ─── */
function renderInspectResult(r, container) {
  const hex = LEVEL_CSS[r.level] || "#64748b";
  const top = (r.signals || []).slice(0, 4);

  container.innerHTML = `
    <div style="background:var(--surface);border:1px solid ${hex}44;border-radius:10px;padding:12px;margin-top:4px;animation:fadeUp 0.25s ease;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <div style="width:48px;height:48px;border-radius:50%;
          background:conic-gradient(from -90deg, ${hex} ${r.score}%, #1e2d45 ${r.score}%);
          display:flex;align-items:center;justify-content:center;
          position:relative;flex-shrink:0;">
          <div style="position:absolute;inset:6px;border-radius:50%;background:var(--surface);"></div>
          <span style="position:relative;z-index:1;font-size:13px;font-weight:900;color:${hex};">${r.score}</span>
        </div>
        <div>
          <div style="font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:1px;
                      color:${hex};margin-bottom:3px;">
            ${LEVEL_ICON[r.level] || ""} ${r.level}
          </div>
          <div style="font-size:10px;color:var(--muted);font-family:var(--mono);word-break:break-all;">
            ${r.host || ""}
          </div>
          <div style="font-size:10.5px;color:var(--text-dim);margin-top:2px;">${r.summary || ""}</div>
        </div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${top.map(s => `
          <span style="display:inline-flex;align-items:center;gap:4px;font-size:10px;
            padding:3px 8px;border-radius:12px;border:1px solid;font-weight:600;
            color:${s.severity==="high"?"#f43f5e":s.severity==="med"?"#f97316":s.severity==="low"?"#f59e0b":"#10b981"};
            border-color:${s.severity==="high"?"#f43f5e44":s.severity==="med"?"#f9731644":s.severity==="low"?"#f59e0b44":"#10b98133"};
            background:${s.severity==="high"?"#f43f5e11":s.severity==="med"?"#f9731611":s.severity==="low"?"#f59e0b11":"#10b98108"};">
            ${SIG_ICON[s.severity]||"🔶"} ${s.title}
          </span>`).join("")}
      </div>
    </div>
  `;
}

/* ─── Load Active Tab Result ─── */
async function loadTabResult(rescan = false) {
  try {
    const card = document.getElementById("verdict-card");
    if (card) card.classList.add("scanning");

    let tabs = [];
    try {
      tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs || !tabs.length) {
        tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      }
    } catch (e) {
      console.warn("tabs.query error:", e);
    }

    const tab = tabs && tabs[0];
    if (!tab || !tab.id) {
      paintResult({ ok: false, host: "No active tab" });
      return;
    }

    const rawUrl = tab.url || tab.pendingUrl || "";

    // Internal browser pages cannot be injected
    if (!rawUrl || /^(chrome|edge|devtools|about|chrome-extension):/i.test(rawUrl)) {
      paintResult({ ok: false, host: rawUrl || "Internal Browser Page" });
      return;
    }

    // 1. INSTANT LOCAL PAINT: Never keep the user waiting on a frozen "Scanning..." spinner!
    let localRes = null;
    if (window.NETRA && typeof window.NETRA.analyzeUrl === "function") {
      localRes = window.NETRA.analyzeUrl(rawUrl);
      paintResult(localRes);
    }

    // 2. Query background memory cache for enriched / email / Gemini result
    try {
      chrome.runtime.sendMessage({ type: "netra-get-cached-result", tabId: tab.id }, (cached) => {
        if (!chrome.runtime.lastError && cached && cached.result) {
          paintResult(cached.result);
          if (aiEnabled && rawUrl.startsWith("http") && !cached.result.geminiResult && window.NETRA_Gemini) {
            NETRA_Gemini.callGemini(rawUrl, cached.result.score, cached.result.signals || [], "")
              .then((geminiResult) => {
                if (geminiResult) {
                  const enriched = NETRA_Gemini.mergeResults(cached.result, geminiResult);
                  paintResult(enriched);
                  chrome.runtime.sendMessage({ type: "netra-score", result: enriched });
                }
              }).catch(() => {});
          }
        } else if (aiEnabled && rawUrl.startsWith("http") && window.NETRA_Gemini) {
          // Trigger live Gemini analysis directly from popup for instantaneous AI verdict
          NETRA_Gemini.callGemini(rawUrl, localRes ? localRes.score : 0, localRes ? localRes.signals : [], "")
            .then((geminiResult) => {
              if (geminiResult) {
                const enriched = NETRA_Gemini.mergeResults(localRes || { url: rawUrl, score: 0 }, geminiResult);
                paintResult(enriched);
                chrome.runtime.sendMessage({ type: "netra-score", result: enriched });
              }
            }).catch(() => {});
        }
      });
    } catch (e) {}

    // 3. Query content script for live in-page DOM scanner results (non-blocking)
    const msgType = rescan ? "netra-rescan" : "netra-get-result";
    try {
      chrome.tabs.sendMessage(tab.id, { type: msgType }, (response) => {
        if (chrome.runtime.lastError) return; // Cleanly ignore disconnected tabs
        if (response) {
          paintResult(response);
        }
      });
    } catch (e) {}
  } catch (err) {
    console.warn("NETRA popup error:", err);
    paintResult({ ok: false });
  }
}

/* ─── Event Listeners ─── */

// Rescan button with spin animation
document.getElementById("btn-rescan").addEventListener("click", function() {
  this.classList.add("spin-anim");
  const lvlEl = document.getElementById("lvl");
  if (lvlEl) lvlEl.textContent = "↺ Rescanning…";
  loadTabResult(true);
  setTimeout(() => this.classList.remove("spin-anim"), 1200);
});

// URL Inspector
document.getElementById("btn-analyze").addEventListener("click", () => {
  const raw = document.getElementById("url-input").value.trim();
  const res = document.getElementById("analyze-res");
  if (!raw) {
    res.innerHTML = '<div style="color:var(--muted);font-size:10.5px;padding:4px 0;">Paste a URL to inspect.</div>';
    return;
  }
  if (!window.NETRA) {
    res.innerHTML = '<div style="color:var(--danger-c);font-size:10.5px;">Engine not loaded. Reload extension.</div>';
    return;
  }

  const inspected = window.NETRA.analyzeUrl(raw);
  renderInspectResult(inspected, res);

  // If AI is enabled, trigger live Gemini AI analysis for the inspected link
  if (aiEnabled && (raw.startsWith("http") || raw.includes(".")) && window.NETRA_Gemini) {
    const aiTargetUrl = raw.startsWith("http") ? raw : `https://${raw}`;
    const aiBox = document.createElement("div");
    aiBox.style.cssText = "font-size:10px;color:var(--violet);padding:6px 0 2px;display:flex;align-items:center;gap:6px;";
    aiBox.innerHTML = '<span class="ai-spinner" style="width:11px;height:11px;"></span> Gemini AI analyzing link…';
    res.appendChild(aiBox);

    NETRA_Gemini.callGemini(aiTargetUrl, inspected.score, inspected.signals || [], "")
      .then((g) => {
        if (g) {
          aiBox.innerHTML = `
            <div style="background:rgba(139,92,246,0.12);border:1px solid rgba(139,92,246,0.3);border-radius:6px;padding:7px 10px;margin-top:6px;color:#e2e8f0;line-height:1.4;">
              <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
                <span style="color:#c084fc;font-weight:800;font-size:9.5px;letter-spacing:0.5px;">✦ GEMINI AI VERDICT:</span>
                <span style="font-weight:800;font-size:10px;color:${g.verdict==='Phishing'?'#f43f5e':g.verdict==='Safe'?'#10b981':'#f59e0b'}">${g.verdict.toUpperCase()} · Risk ${g.geminiScore}/100</span>
              </div>
              <div style="font-size:10px;color:#cbd5e1;">${g.reasoning || ""}</div>
            </div>
          `;
        } else {
          aiBox.innerHTML = '<span style="color:#94a3b8;font-size:10px;">Local heuristic inspection complete.</span>';
        }
      })
      .catch(() => {
        aiBox.innerHTML = '<span style="color:#94a3b8;font-size:10px;">Local heuristic inspection complete.</span>';
      });
  }
});

document.getElementById("btn-clear").addEventListener("click", () => {
  document.getElementById("url-input").value = "";
  document.getElementById("analyze-res").innerHTML = "";
});

document.getElementById("url-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); document.getElementById("btn-analyze").click(); }
});

/* ─── Live Gemini AI Update from Background ─── */
try {
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "netra-gemini-update" && msg.result) {
      paintResult(msg.result);
    }
  });
} catch (e) {
  console.warn("NETRA: could not register live update listener:", e);
}

/* ─── Boot ─── */
loadAIPreference();
loadTabResult();
