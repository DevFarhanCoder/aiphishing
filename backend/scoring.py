"""
Risk scoring & verdict mapping.

Converts a 0-100 risk score into a human-readable risk level and verdict,
and produces a recommended action string.
"""

RISK_LEVELS = [
    (0, 20, "Safe", "No obvious phishing indicators detected"),
    (21, 40, "Low Risk", "Suspicious - review carefully before acting"),
    (41, 60, "Medium Risk", "Suspicious - likely phishing"),
    (61, 80, "High Risk", "Likely Phishing"),
    (81, 100, "Critical", "Highly Dangerous - do not interact"),
]


def score_to_level(score: int) -> dict:
    """Map a numeric score to level + verdict."""
    for lo, hi, level, verdict in RISK_LEVELS:
        if lo <= score <= hi:
            return {"level": level, "verdict": verdict}
    return {"level": "Unknown", "verdict": "Unable to classify"}


def recommendation_for(level: str, has_urls: bool, has_credential_request: bool) -> str:
    """Produce a context-aware recommended action string."""
    if level == "Safe":
        return (
            "No obvious phishing indicators were detected. This analysis does not "
            "guarantee that the message is legitimate - always verify sensitive requests "
            "through official channels."
        )
    if level == "Low Risk":
        return (
            "Some minor suspicious signals were detected. Do not click links or share "
            "personal information without verifying the sender through an official channel."
        )
    if level == "Medium Risk":
        base = "Treat this message as suspicious. "
        if has_credential_request:
            base += "Never share OTPs, passwords, PINs or CVVs - legitimate organizations never ask. "
        if has_urls:
            base += "Do not click any links in the message. "
        base += "Contact the organization directly via a number/website you already trust."
        return base
    if level in ("High Risk", "Critical"):
        parts = ["Do NOT click any links, reply, or share information."]
        if has_credential_request:
            parts.append("Never share OTPs, passwords, PINs, CVVs or banking details.")
        if has_urls:
            parts.append("Do not visit the URLs in this message.")
        parts.append("Report this message as spam / phishing and delete it. If you already interacted, immediately contact your bank and change affected passwords.")
        return " ".join(parts)
    return "Review the message carefully."
