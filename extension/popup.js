/**
 * PhishLens Student Shield — Popup Interface Logic
 * Renders active tab risk gauge, student protection alert, and URL sandbox analyzer.
 */

const COLORS = {
  dangerous: "#dc2626",
  suspicious: "#ea580c",
  caution: "#ca8a04",
  "likely safe": "#16a34a",
  unknown: "#64748b"
};

function paintResult(result) {
  const ring = document.getElementById("ring");
  const scoreNum = document.getElementById("score-num");
  const lvl = document.getElementById("lvl");
  const host = document.getElementById("host");
  const summary = document.getElementById("summary");
  const studentBox = document.getElementById("student-box");
  const studentAdvice = document.getElementById("student-advice");
  const sigs = document.getElementById("sigs");

  if (!result || !result.ok) {
    scoreNum.textContent = "–";
    lvl.textContent = "restricted page";
    lvl.style.background = "#334155";
    lvl.style.color = "#94a3b8";
    ring.style.background = "#1e293b";
    ring.style.border = "3px solid #475569";
    host.textContent = result && result.host ? result.host : "Browser internal or local tab";
    summary.textContent = "Internal browser pages and settings cannot be scanned.";
    studentBox.style.display = "none";
    sigs.innerHTML = '<li class="good"><b>Protected Tab</b><span>This page runs in an isolated browser context.</span></li>';
    return;
  }

  const c = COLORS[result.level] || COLORS.unknown;
  scoreNum.textContent = result.score;
  ring.style.background = c + "22";
  ring.style.border = `3px solid ${c}`;

  lvl.textContent = `${result.level} (${result.score}/100)`;
  lvl.style.background = c + "33";
  lvl.style.color = c;
  lvl.style.border = `1px solid ${c}`;

  host.textContent = result.host || result.url || "";
  summary.textContent = result.summary || "";

  // Student Protection box
  if (result.studentProtection && result.studentProtection.isStudentTargeted) {
    studentBox.style.display = "block";
    const targets = (result.studentProtection.detectedTargets || []).join(", ") || "Campus / University Services";
    const advice = (result.studentProtection.advice && result.studentProtection.advice[0]) ||
      "Do not enter university credentials on this website.";
    studentAdvice.innerHTML = `<div><b>Target:</b> ${targets}</div><div style="margin-top:2px;">${advice}</div>`;
  } else {
    studentBox.style.display = "none";
  }

  // Detected signals
  sigs.innerHTML = "";
  const signals = result.signals || [];
  if (signals.length === 0) {
    sigs.innerHTML = '<li class="good"><b>Clean</b><span>No suspicious phishing signals detected on this site.</span></li>';
  } else {
    for (const s of signals.slice(0, 5)) {
      const li = document.createElement("li");
      li.className = s.severity || "med";
      li.innerHTML = `<b>${s.title}</b><span>${s.detail}</span>`;
      sigs.appendChild(li);
    }
  }
}

async function loadTabResult(rescan = false) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      paintResult({ ok: false });
      return;
    }

    // Don't attempt to scan chrome://, edge://, devtools://
    if (tab.url && /^(chrome|edge|devtools|about|chrome-extension):/i.test(tab.url)) {
      paintResult({ ok: false, host: tab.url });
      return;
    }

    const messageType = rescan ? "pl-rescan" : "pl-get-result";

    chrome.tabs.sendMessage(tab.id, { type: messageType }, (response) => {
      if (chrome.runtime.lastError || !response) {
        // Fallback: check background worker's cached analysis
        chrome.runtime.sendMessage({ type: "pl-get-cached-result", tabId: tab.id }, (cachedResp) => {
          if (cachedResp && cachedResp.result) {
            paintResult(cachedResp.result);
          } else {
            // Local fallback analysis from URL
            if (window.PhishLens && tab.url) {
              const localRes = window.PhishLens.analyzeUrl(tab.url);
              paintResult(localRes);
            } else {
              paintResult({ ok: false, host: tab.url });
            }
          }
        });
      } else {
        paintResult(response);
      }
    });
  } catch (err) {
    console.warn("Popup tab result load error:", err);
    paintResult({ ok: false });
  }
}

// Rescan button
document.getElementById("btn-rescan").addEventListener("click", () => {
  document.getElementById("lvl").textContent = "Rescanning…";
  loadTabResult(true);
});

// Paste-A-Link Analyzer
document.getElementById("btn-analyze").addEventListener("click", () => {
  const inputEl = document.getElementById("url-input");
  const rawUrl = inputEl.value.trim();
  const resContainer = document.getElementById("analyze-res");

  if (!rawUrl) {
    resContainer.innerHTML = '<div style="color:#94a3b8;font-size:11px;">Please enter or paste a URL first.</div>';
    return;
  }

  if (!window.PhishLens) {
    resContainer.innerHTML = '<div style="color:#ef4444;font-size:11px;">Engine error: PhishLens not loaded.</div>';
    return;
  }

  const r = window.PhishLens.analyzeUrl(rawUrl);
  const c = COLORS[r.level] || COLORS.unknown;

  const topSigs = (r.signals || []).slice(0, 4);

  resContainer.innerHTML = `
    <div class="card" style="margin-bottom:0;border-color:${c};">
      <div class="gauge-row">
        <div class="ring" style="background:${c}22;border:3px solid ${c};width:50px;height:50px;font-size:16px;">
          ${r.score}<small>/100</small>
        </div>
        <div class="gauge-info">
          <div><span class="lvl-pill" style="background:${c}33;color:${c};border:1px solid ${c};">${r.level}</span></div>
          <div class="host-label">${r.host || rawUrl}</div>
          <div class="summary-label" style="font-size:11px;">${r.summary}</div>
        </div>
      </div>
      ${r.studentProtection && r.studentProtection.isStudentTargeted ? `
        <div class="student-box" style="margin-top:8px;">
          <b>🛡️ Student Alert</b>
          <div>${r.studentProtection.advice[0] || 'Targeted student threat detected.'}</div>
        </div>` : ''}
      <ul class="signals-list" style="margin-top:8px;">
        ${topSigs.map((s) => `<li class="${s.severity}"><b>${s.title}</b><span>${s.detail}</span></li>`).join("")}
      </ul>
    </div>
  `;
});

// Clear button
document.getElementById("btn-clear").addEventListener("click", () => {
  document.getElementById("url-input").value = "";
  document.getElementById("analyze-res").innerHTML = "";
});

// Enter key in textarea triggers analyze
document.getElementById("url-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    document.getElementById("btn-analyze").click();
  }
});

// Initial load
loadTabResult();
