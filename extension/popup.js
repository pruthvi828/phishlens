/**
 * NETRA — Network Eye for Threat Recognition & Analysis
 * Popup Interface Logic v3.0
 */

const RISK_COLOR = {
  dangerous:     "#ff3b5c",
  suspicious:    "#ff7b00",
  caution:       "#f0a500",
  "likely safe": "#00e87a",
  unknown:       "#6b8196"
};

const RISK_ICON = {
  dangerous:     "🔴",
  suspicious:    "🟠",
  caution:       "🟡",
  "likely safe": "🟢",
  unknown:       "⚪"
};

const SIG_ICON = {
  high: "⚠️",
  med:  "🔶",
  low:  "🔷",
  good: "✅"
};

/**
 * Animate the SVG arc gauge
 */
function setGauge(score, color) {
  const arc = document.getElementById("gauge-arc");
  if (!arc) return;
  const circumference = 2 * Math.PI * 28; // r=28 → 175.9
  const offset = circumference - (score / 100) * circumference;
  arc.style.strokeDashoffset = offset;
  arc.style.stroke = color;
}

/**
 * Render all result data into the NETRA popup
 */
function paintResult(result) {
  const scoreEl   = document.getElementById("score-num");
  const lvlEl     = document.getElementById("lvl");
  const hostEl    = document.getElementById("host");
  const summaryEl = document.getElementById("summary");
  const studentBox    = document.getElementById("student-box");
  const studentAdvice = document.getElementById("student-advice");
  const sigsEl    = document.getElementById("sigs");
  const sigCount  = document.getElementById("sig-count");
  const card      = document.getElementById("verdict-card");

  // Stop scan animation
  if (card) card.classList.remove("scanning");

  if (!result || !result.ok) {
    scoreEl.textContent = "—";
    scoreEl.style.color = "#6b8196";
    setGauge(0, "#6b8196");
    lvlEl.textContent = "Restricted";
    lvlEl.style.background = "rgba(107,129,150,0.15)";
    lvlEl.style.color = "#6b8196";
    hostEl.textContent = result && result.host ? result.host : "Internal browser tab";
    summaryEl.textContent = "Browser internal pages cannot be scanned.";
    studentBox.style.display = "none";
    sigsEl.innerHTML = '<li class="good"><span class="sig-icon">🔒</span><div class="sig-body"><b>Isolated Context</b><span>This page runs in an isolated browser context and is safe.</span></div></li>';
    if (sigCount) sigCount.textContent = "";
    return;
  }

  const c = RISK_COLOR[result.level] || RISK_COLOR.unknown;
  scoreEl.textContent = result.score;
  scoreEl.style.color = c;
  setGauge(result.score, c);

  lvlEl.textContent = `${RISK_ICON[result.level] || "⚪"} ${result.level}`.toUpperCase();
  lvlEl.style.background = c + "22";
  lvlEl.style.color = c;
  lvlEl.style.border = `1px solid ${c}44`;
  lvlEl.style.borderRadius = "4px";
  lvlEl.style.padding = "3px 9px";

  hostEl.textContent = result.host || result.url || "";
  summaryEl.textContent = result.summary || "";

  // Student Protection
  if (result.studentProtection && result.studentProtection.isStudentTargeted) {
    studentBox.style.display = "block";
    const targets = (result.studentProtection.detectedTargets || []).join(", ") || "Campus / University Services";
    const advice  = (result.studentProtection.advice && result.studentProtection.advice[0]) ||
      "Do not enter university credentials here.";
    studentAdvice.innerHTML = `<div><b style="font-size:10px;color:#aaa">Target:</b> ${targets}</div><div style="margin-top:3px;">${advice}</div>`;
  } else {
    studentBox.style.display = "none";
  }

  // Signals
  const signals = result.signals || [];
  if (sigCount) sigCount.textContent = signals.length > 0 ? `${signals.length} found` : "";
  sigsEl.innerHTML = "";

  if (signals.length === 0) {
    sigsEl.innerHTML = '<li class="good"><span class="sig-icon">✅</span><div class="sig-body"><b>No Threats</b><span>No suspicious signals detected on this page.</span></div></li>';
  } else {
    for (const s of signals.slice(0, 6)) {
      const li = document.createElement("li");
      li.className = s.severity || "med";
      li.innerHTML = `<span class="sig-icon">${SIG_ICON[s.severity] || "🔶"}</span><div class="sig-body"><b>${s.title}</b><span>${s.detail}</span></div>`;
      sigsEl.appendChild(li);
    }
  }
}

/**
 * Render a compact inline result for the URL inspector
 */
function renderInspectResult(r, container) {
  const c = RISK_COLOR[r.level] || RISK_COLOR.unknown;
  const topSigs = (r.signals || []).slice(0, 4);

  const advice = r.studentProtection && r.studentProtection.isStudentTargeted
    ? `<div style="margin-top:8px;background:rgba(0,240,200,0.06);border:1px solid rgba(0,240,200,0.18);border-radius:6px;padding:7px 9px;font-size:10.5px;">
        <b style="color:#00f0c8;display:block;font-size:10px;letter-spacing:.5px;margin-bottom:2px;">🎓 STUDENT ALERT</b>
        ${r.studentProtection.advice[0] || "Targeted student threat."}
       </div>` : "";

  container.innerHTML = `
    <div style="background:#0d1422;border:1px solid ${c}44;border-radius:8px;padding:11px;margin-top:2px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <div style="width:46px;height:46px;border-radius:50%;background:${c}15;border:3px solid ${c};
                    display:flex;align-items:center;justify-content:center;flex-shrink:0;
                    font-size:16px;font-weight:900;color:${c};">${r.score}</div>
        <div>
          <div style="font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:1px;
                      background:${c}22;color:${c};border-radius:4px;padding:2px 7px;display:inline-block;">
            ${RISK_ICON[r.level] || ""} ${r.level}
          </div>
          <div style="font-size:10.5px;color:#6b8196;font-family:'JetBrains Mono',monospace;margin-top:3px;word-break:break-all;">${r.host || ""}</div>
          <div style="font-size:11px;margin-top:2px;">${r.summary || ""}</div>
        </div>
      </div>
      ${advice}
      <div style="margin-top:6px;">
        ${topSigs.map(s => `
          <div style="display:flex;gap:7px;align-items:flex-start;padding:5px 8px;background:#111827;border-radius:5px;
                      border-left:3px solid ${s.severity==='high'?'#ff3b5c':s.severity==='med'?'#ff7b00':s.severity==='low'?'#f0a500':'#00e87a'};
                      margin-bottom:4px;font-size:10.5px;">
            <span>${SIG_ICON[s.severity]||"🔶"}</span>
            <div><b style="display:block;font-size:10.5px;">${s.title}</b><span style="color:#6b8196">${s.detail}</span></div>
          </div>`).join("")}
      </div>
    </div>
  `;
}

/**
 * Load the active tab's scan result
 */
async function loadTabResult(rescan = false) {
  try {
    const card = document.getElementById("verdict-card");
    if (card) card.classList.add("scanning");

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      paintResult({ ok: false });
      return;
    }

    if (tab.url && /^(chrome|edge|devtools|about|chrome-extension):/i.test(tab.url)) {
      paintResult({ ok: false, host: tab.url });
      return;
    }

    const messageType = rescan ? "pl-rescan" : "pl-get-result";

    chrome.tabs.sendMessage(tab.id, { type: messageType }, (response) => {
      if (chrome.runtime.lastError || !response) {
        chrome.runtime.sendMessage({ type: "pl-get-cached-result", tabId: tab.id }, (cachedResp) => {
          if (cachedResp && cachedResp.result) {
            paintResult(cachedResp.result);
          } else if (window.PhishLens && tab.url) {
            paintResult(window.PhishLens.analyzeUrl(tab.url));
          } else {
            paintResult({ ok: false, host: tab.url });
          }
        });
      } else {
        paintResult(response);
      }
    });
  } catch (err) {
    console.warn("NETRA popup error:", err);
    paintResult({ ok: false });
  }
}

// Rescan
document.getElementById("btn-rescan").addEventListener("click", () => {
  const lvlEl = document.getElementById("lvl");
  if (lvlEl) { lvlEl.textContent = "Rescanning…"; }
  loadTabResult(true);
});

// Inspect URL
document.getElementById("btn-analyze").addEventListener("click", () => {
  const inputEl = document.getElementById("url-input");
  const rawUrl  = inputEl.value.trim();
  const resContainer = document.getElementById("analyze-res");

  if (!rawUrl) {
    resContainer.innerHTML = '<div style="color:#6b8196;font-size:11px;padding:4px 0;">Please paste a URL to inspect.</div>';
    return;
  }
  if (!window.PhishLens) {
    resContainer.innerHTML = '<div style="color:#ff3b5c;font-size:11px;padding:4px 0;">Engine not loaded. Reload the extension.</div>';
    return;
  }
  renderInspectResult(window.PhishLens.analyzeUrl(rawUrl), resContainer);
});

// Clear
document.getElementById("btn-clear").addEventListener("click", () => {
  document.getElementById("url-input").value = "";
  document.getElementById("analyze-res").innerHTML = "";
});

// Enter key
document.getElementById("url-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    document.getElementById("btn-analyze").click();
  }
});

// Boot
loadTabResult();
