"""
Rule-based phishing indicator detector.

Scans a message for six categories of phishing signals:
  1. Urgency / fear language
  2. Credential / sensitive-info requests
  3. Financial fraud indicators
  4. Suspicious URLs (delegated to url_analyzer)
  5. Impersonation / social engineering
  6. Manipulative language patterns

Each detected signal contributes weighted points to the final risk score.
The engine is intentionally transparent - every point is traceable to a
concrete pattern match, so we can explain WHY a message was flagged.
"""
import re
from url_analyzer import extract_urls, analyze_url

# ---------------------------------------------------------------------------
# Pattern dictionaries. Each entry: (regex_pattern, category, label, weight)
# ---------------------------------------------------------------------------

URGENCY_PATTERNS = [
    (r"\b(urgent|immediately|right now|asap|act now|final notice|last warning)\b", "Urgency", "Uses urgent / immediate-action language", 8),
    (r"\b(within\s+\d+\s+(hours?|minutes?|hrs?|mins?))\b", "Urgency", "Imposes an artificial short deadline", 7),
    (r"\b(account (will be |is )?(blocked|suspended|deactivated|closed|frozen))\b", "Urgency", "Threatens account suspension / blocking", 12),
    (r"\b(verify (your )?account|verification required|confirm (your )?identity)\b", "Urgency", "Demands immediate account / identity verification", 10),
    (r"\b(fail(ed|ure) to (respond|comply|act))\b", "Urgency", "Threatens consequences for inaction", 6),
]

CREDENTIAL_PATTERNS = [
    (r"\b(otp|one[- ]?time[- ]?password)\b", "Credentials", "Requests an OTP / one-time password", 18),
    (r"\b(password|passcode|pass[- ]?word)\b", "Credentials", "Requests password", 15),
    (r"\b(pin\s*(number|code)?|4[- ]?digit\s*pin)\b", "Credentials", "Requests PIN", 12),
    (r"\b(cvv|cvc|card\s*verification)\b", "Credentials", "Requests CVV / card verification code", 18),
    (r"\b(credit\s*card|debit\s*card|card\s*number)\b", "Credentials", "Requests card number", 12),
    (r"\b(aadhaar|aadhar|pan\s*card|social\s*security|ssn)\b", "Credentials", "Requests government / national ID", 15),
    (r"\b(login\s*(credentials|details|info)|username\s*and\s*password)\b", "Credentials", "Requests login credentials", 14),
    (r"\b(bank\s*(account|details|info)|account\s*number|ifsc)\b", "Credentials", "Requests banking details", 10),
]

FINANCIAL_FRAUD_PATTERNS = [
    (r"\b(you (have |'ve )?won|congratulations.*(won|winner|selected))\b", "Financial", "Claims recipient won a prize / lottery", 14),
    (r"\b(lottery|jackpot|lucky\s*draw|prize\s*money)\b", "Financial", "Mentions lottery / jackpot / prize", 10),
    (r"\b(refund|cashback|reward|gift\s*card|free\s*gift)\b", "Financial", "Offers unexpected refund / reward / cashback", 6),
    (r"\b(bitcoin|btc|ethereum|eth|crypto(currency)?|usdt|wallet\s*address)\b", "Financial", "Requests or references cryptocurrency payment", 10),
    (r"\b(upi\s*(id|pin|payment)|scan\s*(this )?qr|paytm|gpay|phonepe)\b", "Financial", "Requests UPI / QR / payment-app action", 8),
    (r"\b(wire\s*transfer|western\s*union|money\s*gram)\b", "Financial", "Requests wire transfer / untraceable payment", 12),
    (r"\b(pay\s*(a\s*)?(fine|fee|charge|penalty))\b", "Financial", "Demands unexpected fee / fine payment", 8),
    (r"\b(inheritance|beneficiary|next\s*of\s*kin|nigerian\s*prince)\b", "Financial", "Classic advance-fee scam language", 15),
]

IMPERSONATION_PATTERNS = [
    (r"\b(bank\s*of|hdfc|icici|sbi|axis|kotak|chase|wells\s*fargo)\b", "Impersonation", "Claims to represent a bank", 5),
    (r"\b(irs|income\s*tax|hmrc|government|customs|police)\b", "Impersonation", "Claims to represent a government agency", 10),
    (r"\b(fedex|dhl|ups|usps|india\s*post|blue\s*dart|delivery\s*(company|service))\b", "Impersonation", "Claims to be a delivery service", 10),
    (r"\b(package|parcel|shipment)\s+(delivery|could\s*not\s*be\s*(completed|delivered)|is\s*(on\s*hold|pending))\b", "Impersonation", "Uses package / delivery failure framing (common scam hook)", 8),
    (r"\b(confirm|update|verify)\s+(your\s+)?(delivery|shipping|address|information|details)\b", "Impersonation", "Asks to confirm/update delivery or address info (delivery scam hook)", 8),
    (r"\b(microsoft|apple|google|amazon|netflix|paypal)\s*(support|team|security)\b", "Impersonation", "Claims to be tech-company support", 10),
    (r"\b(kyc|know\s*your\s*customer|re[- ]?verify)\b", "Impersonation", "Requests KYC re-verification (common scam vector)", 12),
    (r"\b(customer\s*(care|support|service))\s*(team|dept|department)?\b", "Impersonation", "Claims to be customer support", 4),
    (r"\b(hr|recruit(er|ment)|job\s*offer|hiring\s*manager)\b", "Impersonation", "Job / recruitment framing (common scam)", 5),
]

LANGUAGE_PATTERNS = [
    (r"[A-Z]{6,}", "Language", "Uses excessive capitalization / SHOUTING", 4),
    (r"!{2,}", "Language", "Uses excessive exclamation marks", 3),
    (r"\b(click\s*(here|now|below|the\s*link))\b", "Language", "Uses generic 'click here' call-to-action", 6),
    (r"\b(dear\s*(customer|user|client|sir/madam))\b", "Language", "Uses impersonal generic greeting", 4),
    (r"\b(do\s*not\s*(share|tell|inform)|keep\s*this\s*(secret|confidential))\b", "Language", "Instructs recipient to hide the message", 10),
]

ALL_CATEGORIES = [
    URGENCY_PATTERNS,
    CREDENTIAL_PATTERNS,
    FINANCIAL_FRAUD_PATTERNS,
    IMPERSONATION_PATTERNS,
    LANGUAGE_PATTERNS,
]


def _scan_patterns(message: str) -> list[dict]:
    """Return a de-duplicated list of matched indicators."""
    findings = []
    seen_labels = set()
    # Language-pattern rules that inspect case must be matched case-sensitively;
    # everything else is case-insensitive.
    CASE_SENSITIVE_LABELS = {
        "Uses excessive capitalization / SHOUTING",
    }
    for group in ALL_CATEGORIES:
        for pattern, category, label, weight in group:
            flags = 0 if label in CASE_SENSITIVE_LABELS else re.IGNORECASE
            if re.search(pattern, message, flags=flags) and label not in seen_labels:
                findings.append({
                    "category": category,
                    "label": label,
                    "weight": weight,
                })
                seen_labels.add(label)
    return findings


def analyze_message(message: str) -> dict:
    """
    Full analysis pipeline. Returns:
      - indicators: list of {category, label, weight}
      - url_findings: per-URL structured analysis
      - rule_score: 0..100 aggregated score from indicators + URLs
    """
    message = message or ""
    text_findings = _scan_patterns(message)

    urls = extract_urls(message)
    url_findings = [analyze_url(u) for u in urls]

    # URL contribution: each URL adds points based on its risk level
    url_score = 0
    for uf in url_findings:
        if uf["risk"] == "High":
            url_score += 25
        elif uf["risk"] == "Medium":
            url_score += 12
        else:
            url_score += 3  # Even a "clean" URL gets a small nudge - links in
                             # SMS/email are inherently a phishing vector.

    text_score = sum(item["weight"] for item in text_findings)

    # Cross-signal boost: credential request + urgency + URL is a strong
    # phishing fingerprint. Boost when at least two of the three co-occur.
    categories_present = {f["category"] for f in text_findings}
    boost = 0
    strong_signals = {
        "Credentials" in categories_present,
        "Urgency" in categories_present,
        len(url_findings) > 0,
    }
    if sum(strong_signals) >= 2:
        boost = 10
    if sum(strong_signals) == 3:
        boost = 20

    raw_score = text_score + url_score + boost
    # Cap at 100. Use a light non-linear curve so mid-signal messages don't
    # instantly hit 100.
    final_score = min(100, int(raw_score))

    return {
        "indicators": text_findings,
        "url_findings": url_findings,
        "rule_score": final_score,
        "boost_applied": boost,
    }
