"""explanation_engine.py - turns phishing red flags into safe, evidence-based explanations.

Standard library only.

Main API:
    generate_explanation(red_flags, source_text=None) -> dict
    detect_red_flags(text) -> list   (simple helper so the module is runnable/testable alone)

Input red flag format (from your detector):
    {"type": "Urgency", "evidence": "act now"}
Type names are matched loosely ("urgent", "otp", "url", "prize", ...).
"""

import re

URGENCY = "Urgency"
PAYMENT = "Payment Request"
OTP = "OTP/Password Theft"
URL = "Suspicious URL"
REWARD = "Unrealistic Reward"
IMPERSONATION = "Impersonation"
UNKNOWN = "Unknown"

# Hedged wording on purpose: we flag risk signals, we never claim certainty.
_REASONS = {
    URGENCY: "Pressures immediate action, which is a common tactic to stop people from checking.",
    PAYMENT: "Asks for money or fees, which legitimate offers rarely require upfront.",
    OTP: "Asks for an OTP or password, which genuine organizations do not request.",
    URL: "Link has traits often seen in phishing (shortener, odd domain, or no HTTPS).",
    REWARD: "Promises a reward or guaranteed outcome that seems too good to be true.",
    IMPERSONATION: "May be posing as an official team or authority; this should be verified.",
    UNKNOWN: "Flagged by the detector as potentially suspicious; the specific reason is unknown.",
}

_NEXT_ACTIONS = [  # (type, action) in priority order
    (OTP, "Do not share any OTP or password. Contact the organization through its official website or phone number."),
    (PAYMENT, "Do not send money. Verify the request through official channels first."),
    (URL, "Do not click the link. Visit the official website directly by typing its address."),
    (IMPERSONATION, "Verify the sender's identity through official channels before responding."),
    (REWARD, "Do not act on the offer. Verify it through official channels."),
    (URGENCY, "Take your time and verify through official channels."),
]
_DEFAULT_ACTION = "Verify through official channels."
_NO_FLAGS_ACTION = "No red flags were provided. Stay cautious and verify through official channels if unsure."

_ALIASES = {
    URGENCY: {"urgency", "urgent", "pressure", "timepressure", "deadline"},
    PAYMENT: {"payment", "paymentrequest", "paymentrequests", "fee", "money", "moneyrequest"},
    OTP: {"otp", "password", "otppasswordtheft", "otptheft", "passwordtheft",
          "credential", "credentials", "credentialtheft"},
    URL: {"url", "link", "suspiciousurl", "suspiciouslink", "suspiciousurls", "maliciouslink"},
    REWARD: {"reward", "prize", "lottery", "unrealisticreward", "unrealisticrewards", "toogoodtobetrue"},
    IMPERSONATION: {"impersonation", "impersonate", "spoofing", "authority", "fakeauthority", "brandimpersonation"},
}
_ALIAS_LOOKUP = {alias: canon for canon, names in _ALIASES.items() for alias in names}


def _canonical_type(raw):
    if not isinstance(raw, str):
        return UNKNOWN
    key = re.sub(r"[^a-z]", "", raw.lower())
    return _ALIAS_LOOKUP.get(key, UNKNOWN)


def _parse_flag(flag):
    """Return (type_label, evidence) or None if the flag is unusable."""
    if isinstance(flag, dict):
        raw_type = flag.get("type")
        evidence = flag.get("evidence")
    elif isinstance(flag, (tuple, list)) and len(flag) == 2:
        raw_type, evidence = flag
    else:
        return None
    # Never invent evidence: no evidence string -> no flag.
    if not isinstance(evidence, str) or not evidence.strip():
        return None
    return _canonical_type(raw_type), evidence


def generate_explanation(red_flags, source_text=None):
    """Build an explanation dict from red flags.

    red_flags:   list of {"type": ..., "evidence": ...}; None/empty/malformed is handled safely.
    source_text: optional original message. If given, flags whose evidence is not an
                 exact substring of it are dropped (guards against invented evidence).
    """
    flags, seen = [], set()
    if isinstance(red_flags, (list, tuple)):
        for item in red_flags:
            parsed = _parse_flag(item)
            if parsed is None:
                continue
            ftype, evidence = parsed
            if isinstance(source_text, str) and evidence not in source_text:
                continue
            if (ftype, evidence) in seen:
                continue
            seen.add((ftype, evidence))
            flags.append({"type": ftype, "evidence": evidence, "reason": _REASONS[ftype]})

    if not flags:
        return {"red_flags": [], "next_action": _NO_FLAGS_ACTION}

    present = {f["type"] for f in flags}
    next_action = next((a for t, a in _NEXT_ACTIONS if t in present), _DEFAULT_ACTION)
    return {"red_flags": flags, "next_action": next_action}


# --------------------------------------------------------------------------
# Minimal rule-based detector (helper for integration demos and tests).
# Evidence is always an exact substring of the input text.
# --------------------------------------------------------------------------
_RULES = [
    (URGENCY, re.compile(
        r"\b(?:act now|urgent(?:ly)?|immediately|last chance|final warning|hurry|"
        r"within \d+ (?:hours?|minutes?)|expires? (?:today|soon))\b", re.I)),
    (PAYMENT, re.compile(
        r"\b(?:pay|send|transfer|deposit)\b[^.!?\n]{0,40}?\b(?:processing fee|registration fee|"
        r"security deposit|upi|gift cards?|crypto|bitcoin|western union)\b", re.I)),
    (OTP, re.compile(
        r"\b(?:share|send|tell|enter|provide|reply with)\b[^.!?\n]{0,30}?\b(?:otp|password|pin|cvv)\b", re.I)),
    (REWARD, re.compile(
        r"\b(?:you (?:have )?won|lottery|claim your (?:reward|prize)|free (?:laptop|iphone)|"
        r"100% (?:scholarship|placement)|guaranteed (?:job|selection|scholarship))\b", re.I)),
    (IMPERSONATION, re.compile(
        r"\b(?:official )?(?:hr team|hr department|customer care|bank officer|"
        r"income tax department|cyber police)\b", re.I)),
]
_URL_RE = re.compile(r"(?:https?://|www\.)\S+|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|t\.co|goo\.gl)/\S+", re.I)
_SHORTENERS = ("bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl")
_BAD_TLDS = (".xyz", ".top", ".click", ".live", ".info", ".zip")
_BAD_WORDS = ("login", "verify", "secure", "account", "update")
_NEGATION_RE = re.compile(r"(?:\bnot|\bnever|n't)\s+(?:\w+\s+){0,2}$", re.I)


def _url_is_suspicious(url):
    low = url.lower()
    host = re.sub(r"^https?://", "", low).split("/")[0].split(":")[0]
    return (
        low.startswith("http://")
        or any(host == s or host.endswith("." + s) for s in _SHORTENERS)
        or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) is not None
        or host.endswith(_BAD_TLDS)
        or ("-" in host and any(w in host for w in _BAD_WORDS))
    )


def detect_red_flags(text):
    """Return a list of {"type", "evidence"} dicts found in text, ordered by position."""
    if not isinstance(text, str) or not text:
        return []
    found = []
    for ftype, pattern in _RULES:
        for m in pattern.finditer(text):
            # Skip warnings like "never share your OTP".
            if ftype == OTP and _NEGATION_RE.search(text[max(0, m.start() - 20):m.start()]):
                continue
            found.append((m.start(), ftype, m.group(0)))
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)\"'")
        if url and _url_is_suspicious(url):
            found.append((m.start(), URL, url))
    found.sort(key=lambda x: x[0])
    return [{"type": t, "evidence": e} for _, t, e in found]


# --------------------------------------------------------------------------
# Quick tests: run `python explanation_engine.py` (or with pytest).
# --------------------------------------------------------------------------
def _types(result):
    return {f["type"] for f in result["red_flags"]}


def _check_shape(result, text):
    assert set(result) == {"red_flags", "next_action"}
    assert isinstance(result["next_action"], str) and result["next_action"]
    for f in result["red_flags"]:
        assert set(f) == {"type", "evidence", "reason"}
        assert f["evidence"] in text  # evidence must be exact


def test_scholarship_scam():
    text = ("Congratulations! You have won a 100% scholarship of Rs 2,00,000. "
            "Pay Rs 5,000 processing fee via UPI to claim. Act now: bit.ly/sch0lar")
    result = generate_explanation(detect_red_flags(text), source_text=text)
    _check_shape(result, text)
    assert {REWARD, PAYMENT, URGENCY, URL} <= _types(result)


def test_fake_internship():
    text = ("Official HR Team of Google: You are selected for an internship! "
            "Pay Rs 1,500 registration fee today. Verify at http://google-careers-login.xyz urgently.")
    result = generate_explanation(detect_red_flags(text), source_text=text)
    _check_shape(result, text)
    assert {IMPERSONATION, PAYMENT, URL, URGENCY} <= _types(result)


def test_otp_theft():
    text = "Dear customer, your account is blocked. Share your OTP immediately to unblock it."
    result = generate_explanation(detect_red_flags(text), source_text=text)
    _check_shape(result, text)
    assert {OTP, URGENCY} <= _types(result)
    assert "OTP" in result["next_action"]


def test_legitimate_college_notice():
    text = ("Notice: Classes resume on Monday. Please check the updated timetable "
            "on the college website. Never share your password with anyone.")
    result = generate_explanation(detect_red_flags(text), source_text=text)
    assert result["red_flags"] == []
    # Empty, None and unknown input must be handled safely, with no invented evidence.
    assert generate_explanation(None)["red_flags"] == []
    assert generate_explanation([{"type": "Mystery"}, "junk", 42])["red_flags"] == []
    unknown = generate_explanation([{"type": "Mystery", "evidence": "odd text"}])
    assert unknown["red_flags"][0]["type"] == UNKNOWN


def test_legitimate_fee_reminder():
    text = ("Reminder: Semester fee is due on 31 Oct. "
            "Please pay through the official college portal or the accounts office.")
    result = generate_explanation(detect_red_flags(text), source_text=text)
    assert result["red_flags"] == []


if __name__ == "__main__":
    import json
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
    demo = "Act now! Share your OTP immediately."
    print(json.dumps(generate_explanation(detect_red_flags(demo), source_text=demo), indent=2))