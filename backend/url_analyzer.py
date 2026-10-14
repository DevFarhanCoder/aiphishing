"""
URL Analyzer for phishing detection.

Passively analyzes URLs extracted from text messages. Does NOT visit or execute
any URL. Detects suspicious characteristics such as HTTP-only URLs, IP-based
URLs, URL shorteners, excessive subdomains, suspicious TLDs, and obfuscation.
"""
import re
from urllib.parse import urlparse

# Known URL shortener services (partial list of the most abused ones)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "bl.ink", "shorturl.at",
    "tiny.cc", "rb.gy", "s.id", "clck.ru", "t.ly", "zpr.io", "lnkd.in",
}

# TLDs commonly abused by phishing campaigns (research-based)
SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "link", "click", "top", "xyz", "tk", "ml", "cf", "ga", "buzz",
    "rest", "fit", "loan", "men", "download", "racing", "faith",
}

# Brands most commonly impersonated. If a domain contains the brand name but
# is NOT the official domain, it is highly suspicious (typosquatting).
POPULAR_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "facebook": ["facebook.com", "fb.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "sbi": ["onlinesbi.com", "sbi.co.in"],
    "axis": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
}

URL_REGEX = re.compile(
    r"(?i)(?<![\w@])((?:https?://|www\.)[^\s<>()\[\]{}'\"]+|"
    r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>()\[\]{}'\"]*)?)"
)
IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def extract_urls(text: str) -> list[str]:
    """Extract all URL-like strings from the provided text."""
    matches = URL_REGEX.findall(text or "")
    urls = []
    for m in matches:
        # Strip trailing punctuation that likely isn't part of the URL
        u = m.rstrip(".,;:!?)")
        if not u.lower().startswith(("http://", "https://")):
            u = "http://" + u
        urls.append(u)
    return urls


def _get_registrable(hostname: str) -> str:
    """Best-effort last-two-labels extraction (no PSL dependency)."""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def analyze_url(url: str) -> dict:
    """Analyze a single URL and return structured findings."""
    findings = {
        "url": url,
        "https": False,
        "ip_based": False,
        "shortener": False,
        "suspicious_domain": False,
        "excessive_subdomains": False,
        "suspicious_tld": False,
        "obfuscated": False,
        "brand_impersonation": None,
        "reasons": [],
        "risk": "Low",
    }

    try:
        parsed = urlparse(url)
    except Exception:
        findings["reasons"].append("URL failed to parse")
        findings["risk"] = "High"
        return findings

    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()

    findings["https"] = scheme == "https"
    if not findings["https"]:
        findings["reasons"].append("Uses insecure HTTP (no TLS)")

    if host and IP_REGEX.match(host):
        findings["ip_based"] = True
        findings["reasons"].append("Uses a raw IP address instead of a domain")

    registrable = _get_registrable(host) if host else ""
    if registrable in URL_SHORTENERS:
        findings["shortener"] = True
        findings["reasons"].append(f"Uses URL shortener ({registrable}) which hides the real destination")

    labels = host.split(".") if host else []
    if len(labels) >= 5:
        findings["excessive_subdomains"] = True
        findings["reasons"].append("Excessive number of subdomains")

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        findings["suspicious_tld"] = True
        findings["reasons"].append(f"Uses a TLD commonly abused by phishing (.{tld})")

    # Obfuscation: '@' in URL, hex-encoded chars in host, or unusual chars
    if "@" in (parsed.netloc or ""):
        findings["obfuscated"] = True
        findings["reasons"].append("Uses '@' obfuscation - real host is after the @ symbol")
    if "%" in host or any(ch in host for ch in ["xn--"]):
        findings["obfuscated"] = True
        findings["reasons"].append("Uses percent-encoding or punycode which may hide the real host")

    # Brand impersonation: the brand name appears in the host, but the host is
    # NOT an official domain. Example: paypal-secure-login.com
    for brand, official in POPULAR_BRANDS.items():
        if brand in host and registrable not in official:
            findings["brand_impersonation"] = brand
            findings["reasons"].append(f"May impersonate '{brand}' (host is not an official {brand} domain)")
            break

    # Suspicious keywords in the path (e.g. verify, login-secure)
    lowered_url = url.lower()
    if any(kw in lowered_url for kw in ["verify", "secure-login", "account-update", "confirm-identity"]):
        findings["suspicious_domain"] = True
        findings["reasons"].append("URL path contains phishing-style keywords")

    # Aggregate risk
    high_signals = sum([
        findings["ip_based"],
        findings["brand_impersonation"] is not None,
        findings["obfuscated"],
    ])
    medium_signals = sum([
        findings["shortener"],
        findings["suspicious_tld"],
        findings["excessive_subdomains"],
        not findings["https"],
        findings["suspicious_domain"],
    ])

    if high_signals >= 1 or medium_signals >= 3:
        findings["risk"] = "High"
    elif medium_signals >= 1:
        findings["risk"] = "Medium"
    else:
        findings["risk"] = "Low"

    return findings
