
const API_URL = "http://127.0.0.1:8000/analyze";

const form = document.getElementById("analyze-form");
const senderInput = document.getElementById("sender");
const messageInput = document.getElementById("message");
const analyzeButton = document.getElementById("analyze-btn");
const buttonLabel = document.getElementById("button-label");
const buttonIcon = document.getElementById("button-icon");
const charCount = document.getElementById("char-count");
const formError = document.getElementById("form-error");

const emptyState = document.getElementById("empty-state");
const loadingState = document.getElementById("loading-state");
const resultContent = document.getElementById("result-content");

const samples = {
  normal: {
    sender: "placement@college.example",
    message:
      "The college placement cell will conduct a campus recruitment session on Friday at 10 AM. Please check the official college portal for the schedule."
  },
  scholarship: {
    sender: "scholarship-awards.example",
    message:
      "Congratulations! You have won a scholarship worth ₹50,000. Pay ₹500 immediately to confirm your eligibility. Click the link below before the offer expires today."
  },
  credentials: {
    sender: "account-security.example",
    message:
      "Your college account will be suspended immediately. Reply with your password and OTP to prevent deactivation."
  }
};

// Update the character counter.
messageInput.addEventListener("input", () => {
  charCount.textContent = `${messageInput.value.length} / 5000`;
  hideError();
});

// Fill a sample message without sending it to the backend.
document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    const sample = samples[button.dataset.sample];

    senderInput.value = sample.sender;
    messageInput.value = sample.message;
    charCount.textContent = `${sample.message.length} / 5000`;

    hideError();
    messageInput.focus();
  });
});

function hideError() {
  formError.hidden = true;
  formError.textContent = "";
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

function setView(view) {
  emptyState.hidden = view !== "empty";
  loadingState.hidden = view !== "loading";
  resultContent.hidden = view !== "result";
}

function setLoading(isLoading) {
  analyzeButton.disabled = isLoading;
  buttonLabel.textContent = isLoading
    ? "Analyzing message..."
    : "Analyze message";

  buttonIcon.textContent = isLoading ? "…" : "⌕";
  analyzeButton.setAttribute("aria-busy", String(isLoading));
}

function normalizeClassification(value, score) {
  const label = String(value || "")
    .toUpperCase()
    .replace(/[-_]/g, " ");

  if (["HIGH RISK", "HIGH", "MALICIOUS"].includes(label)) {
    return "HIGH RISK";
  }

  if (["SUSPICIOUS", "MEDIUM", "MODERATE"].includes(label)) {
    return "SUSPICIOUS";
  }

  if ([
    "SAFE",
    "SAFE LOOKING",
    "LOW",
    "LOW RISK"
  ].includes(label)) {
    return "SAFE-LOOKING";
  }

  // Only use fallback thresholds if the backend did not provide
  // a recognized classification.
  if (score >= 60) return "HIGH RISK";
  if (score >= 30) return "SUSPICIOUS";
  return "SAFE-LOOKING";
}

function normalizeFlag(flag) {
  if (typeof flag === "string") {
    return {
      type: "Warning sign",
      evidence: "",
      reason: flag
    };
  }

  return {
    type: String(flag?.type || flag?.category || flag?.title || "Warning sign"),
    evidence: String(flag?.evidence || flag?.matched_text || ""),
    reason: String(flag?.reason || flag?.description || flag?.explanation || "Review this indicator carefully.")
  };
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  if (text !== undefined) {
    // Use textContent to avoid interpreting model output as HTML.
    element.textContent = text;
  }

  return element;
}

function renderFlags(flags) {
  const container = document.getElementById("red-flags");
  container.replaceChildren();

  document.getElementById("flag-count").textContent =
    String(flags.length);

  if (flags.length === 0) {
    const box = makeElement("div", "no-flags");
    box.append(
      makeElement("strong", "", "No significant warning signs returned"),
      makeElement(
        "p",
        "",
        "This does not guarantee safety. Verify unexpected requests independently."
      )
    );

    container.append(box);
    return;
  }

  flags.forEach((flag) => {
    const card = makeElement("article", "flag-card");
    const icon = makeElement("div", "flag-icon", "!");
    const content = makeElement("div", "flag-content");
    const title = makeElement("h4", "", flag.type);

    content.append(title);

    if (flag.evidence) {
      content.append(
        makeElement("div", "flag-evidence", `Evidence: "${flag.evidence}"`)
      );
    }

    content.append(makeElement("p", "", flag.reason));
    card.append(icon, content);
    container.append(card);
  });
}

function renderResult(data) {
  // Accept the documented API contract and common alternative names.
  const rawScore = data.risk_score ?? data.score;

  if (
    rawScore === undefined ||
    rawScore === null ||
    rawScore === "" ||
    !Number.isFinite(Number(rawScore)) ||
    Number(rawScore) < 0 ||
    Number(rawScore) > 100
  ) {
    throw new Error("The backend returned an invalid risk score.");
  }

  const score = Number(rawScore);
  const classification = normalizeClassification(
    data.classification ?? data.label ?? data.risk_level,
    score
  );

  const flags = data.red_flags ?? data.flags ?? data.indicators ?? [];

  if (!Array.isArray(flags)) {
    throw new Error("The backend returned an invalid warning-sign list.");
  }

  const normalizedFlags = flags.map(normalizeFlag);

  const riskClass =
    classification === "HIGH RISK"
      ? "risk-high"
      : classification === "SUSPICIOUS"
        ? "risk-medium"
        : "risk-low";

  const riskCard = document.getElementById("risk-card");
  riskCard.classList.remove("risk-low", "risk-medium", "risk-high");
  riskCard.classList.add(riskClass);

  document.getElementById("risk-score").textContent = String(score);
  document.getElementById("risk-badge").textContent = classification;
  document.getElementById("risk-symbol").textContent =
    classification === "HIGH RISK" ? "!" :
    classification === "SUSPICIOUS" ? "!" : "✓";

  document.getElementById("risk-summary").textContent =
    data.summary ||
    (classification === "HIGH RISK"
      ? "Strong warning signs were identified. Proceed with caution."
      : classification === "SUSPICIOUS"
        ? "Review the warning signs before taking action."
        : "No significant warning signs were reported. This is not a safety guarantee.");

  const riskFill = document.getElementById("risk-fill");
  riskFill.style.width = `${score}%`;

  document.getElementById("risk-meter").setAttribute(
    "aria-valuenow",
    String(score)
  );

  renderFlags(normalizedFlags);

  const nextAction =
    data.next_action ??
    data.recommended_action ??
    data.recommendation;

  document.getElementById("next-action").textContent =
    typeof nextAction === "string" && nextAction.trim()
      ? nextAction
      : "Verify the message through an independently confirmed official channel before acting.";

  setView("result");
  document.getElementById("results").scrollIntoView({
    behavior: "smooth",
    block: "nearest"
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideError();

  const sender = senderInput.value.trim();
  const message = messageInput.value.trim();

  if (!message) {
    showError("Please paste a message before starting the analysis.");
    messageInput.focus();
    return;
  }

  if (message.length > 5000) {
    showError("Please keep the message under 5,000 characters.");
    return;
  }

  setLoading(true);
  setView("loading");

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        sender,
        message
      })
    });

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error("The /analyze endpoint was not found. Check the backend URL.");
      }

      if (response.status === 422) {
        throw new Error("The backend rejected the request. Check the API field names.");
      }

      throw new Error(`The analysis server returned HTTP ${response.status}.`);
    }

    const data = await response.json();

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("The server returned an unexpected response format.");
    }

    renderResult(data);
  } catch (error) {
    setView("empty");

    if (error instanceof TypeError) {
      showError(
        "Could not connect to the Python backend. Make sure it is running and CORS is configured."
      );
    } else {
      showError(error.message || "Analysis failed. Please try again.");
    }
  } finally {
    setLoading(false);
  }
});

document.getElementById("reset-btn").addEventListener("click", () => {
  messageInput.value = "";
  senderInput.value = "";
  charCount.textContent = "0 / 5000";

  hideError();
  setView("empty");
  messageInput.focus();
});
