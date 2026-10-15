"""
FastAPI server for the AI Phishing Attack Detector.

Endpoints (all prefixed with /api):
  POST /api/analyze         - Analyze a message. Returns risk score, level,
                              verdict, indicators, URL analysis, and (best-effort)
                              AI-generated natural-language explanation.
  GET  /api/samples         - Returns labeled sample messages for the UI.
  GET  /api/                - Health check.

The scoring is deterministic and rule-based (see detector.py + scoring.py).
The LLM is used ONLY to generate the human-readable "why was this flagged"
explanation - it never influences the numeric score. If the LLM call fails,
we fall back to a deterministic explanation built from the matched indicators.
"""
import os
import logging
import asyncio
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from detector import analyze_message
from scoring import score_to_level, recommendation_for

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("phishing-detector")

EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")

app = FastAPI(title="AI Phishing Attack Detector")
api_router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)


class Indicator(BaseModel):
    category: str
    label: str
    weight: int


class UrlFinding(BaseModel):
    url: str
    https: bool
    ip_based: bool
    shortener: bool
    suspicious_domain: bool
    excessive_subdomains: bool
    suspicious_tld: bool
    obfuscated: bool
    brand_impersonation: Optional[str] = None
    reasons: List[str]
    risk: str


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    verdict: str
    indicators: List[str]
    detailed_indicators: List[Indicator]
    url_findings: List[UrlFinding]
    recommendation: str
    ai_explanation: str
    explainable_reasons: List[dict]


# ---------------------------------------------------------------------------
# LLM explanation (best-effort, non-blocking)
# ---------------------------------------------------------------------------
async def generate_ai_explanation(message: str, score: int, level: str, indicators: list[dict], url_findings: list[dict]) -> str:
    """Ask Claude Sonnet to produce a short natural-language explanation.
    Falls back to a deterministic explanation if the LLM is unavailable."""
    if not EMERGENT_LLM_KEY or not indicators and not url_findings:
        return _fallback_explanation(score, level, indicators, url_findings)

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage  # type: ignore

        indicator_lines = "\n".join(f"- [{i['category']}] {i['label']}" for i in indicators) or "- (no rule-based indicators matched)"
        url_lines = "\n".join(
            f"- {u['url']} (risk={u['risk']}, reasons={', '.join(u['reasons']) or 'none'})"
            for u in url_findings
        ) or "- (no URLs in message)"

        system = (
            "You are a cybersecurity analyst. You will receive a suspicious message "
            "along with a pre-computed rule-based analysis. Your job is to write a "
            "concise (3-5 sentences) plain-English explanation for a non-technical "
            "user of WHY the message received its risk score. Do NOT invent new "
            "indicators - only reference the ones provided. Do not repeat the score. "
            "Do not start with phrases like 'This message'. Be direct and practical."
        )
        prompt = (
            f"Risk score: {score}/100 ({level})\n\n"
            f"Detected indicators:\n{indicator_lines}\n\n"
            f"URL analysis:\n{url_lines}\n\n"
            f"Message:\n\"\"\"\n{message[:2000]}\n\"\"\""
        )

        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"phish-{hash(message) & 0xffffffff}",
            system_message=system,
        ).with_model("anthropic", "claude-sonnet-4-6")

        # Use send_message with a short timeout so the endpoint never hangs.
        result = await asyncio.wait_for(chat.send_message(UserMessage(text=prompt)), timeout=15.0)
        text = result if isinstance(result, str) else getattr(result, "content", "") or str(result)
        text = text.strip()
        return text or _fallback_explanation(score, level, indicators, url_findings)
    except Exception as e:
        logger.warning("LLM explanation failed, using fallback: %s", e)
        return _fallback_explanation(score, level, indicators, url_findings)


def _fallback_explanation(score: int, level: str, indicators: list[dict], url_findings: list[dict]) -> str:
    if not indicators and not url_findings:
        return (
            "No known phishing patterns were detected in the message text or its URLs. "
            "This does not guarantee legitimacy - always verify sensitive requests through "
            "an official channel."
        )
    top = [i["label"] for i in sorted(indicators, key=lambda x: -x["weight"])[:3]]
    parts = []
    if top:
        parts.append("Key signals detected: " + "; ".join(top) + ".")
    if url_findings:
        risky_urls = [u for u in url_findings if u["risk"] in ("High", "Medium")]
        if risky_urls:
            parts.append(f"The message also contains {len(risky_urls)} suspicious URL(s).")
    parts.append(
        f"Combined, these signals produced a {level} rating. "
        "Legitimate organizations rarely combine urgency with credential requests or embedded links."
    )
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Explainable reasons - group indicators into human-readable categories
# ---------------------------------------------------------------------------
CATEGORY_DESCRIPTIONS = {
    "Urgency": "The message pressures the recipient to act immediately, a classic phishing tactic to bypass careful reading.",
    "Credentials": "The message requests sensitive authentication information (OTP, password, PIN, CVV). Legitimate organizations never ask for these over SMS or email.",
    "Financial": "The message contains financial-fraud patterns such as prizes, refunds, crypto or unexpected payment requests.",
    "Impersonation": "The message claims to represent a bank, government agency, delivery service, or tech company - a common social-engineering vector.",
    "Language": "The message uses manipulative language patterns (excessive urgency, capitalization, generic greetings, or secrecy instructions).",
    "URL": "The message contains URL(s) with characteristics commonly associated with phishing.",
}


def build_explainable_reasons(indicators: list[dict], url_findings: list[dict]) -> list[dict]:
    seen_categories = {}
    for i in indicators:
        seen_categories.setdefault(i["category"], []).append(i["label"])
    if any(u["risk"] in ("High", "Medium") for u in url_findings):
        seen_categories.setdefault("URL", [])
        for u in url_findings:
            if u["risk"] in ("High", "Medium"):
                seen_categories["URL"].extend(u["reasons"])

    result = []
    for cat, items in seen_categories.items():
        result.append({
            "category": cat,
            "description": CATEGORY_DESCRIPTIONS.get(cat, ""),
            "matches": list(dict.fromkeys(items))[:6],  # de-dup, cap 6
        })
    return result


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@api_router.get("/")
async def root():
    return {"service": "AI Phishing Attack Detector", "status": "ok"}


@api_router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    message = req.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Please enter a message to analyze.")

    try:
        analysis = analyze_message(message)
    except Exception as e:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail="Unable to analyze the message. Please try again.") from e

    score = analysis["rule_score"]
    level_info = score_to_level(score)
    level = level_info["level"]
    verdict = level_info["verdict"]

    has_urls = len(analysis["url_findings"]) > 0
    has_creds = any(i["category"] == "Credentials" for i in analysis["indicators"])
    recommendation = recommendation_for(level, has_urls, has_creds)

    ai_explanation = await generate_ai_explanation(
        message, score, level, analysis["indicators"], analysis["url_findings"]
    )

    explainable = build_explainable_reasons(analysis["indicators"], analysis["url_findings"])

    return AnalyzeResponse(
        risk_score=score,
        risk_level=level,
        verdict=verdict,
        indicators=[i["label"] for i in analysis["indicators"]],
        detailed_indicators=[Indicator(**i) for i in analysis["indicators"]],
        url_findings=[UrlFinding(**u) for u in analysis["url_findings"]],
        recommendation=recommendation,
        ai_explanation=ai_explanation,
        explainable_reasons=explainable,
    )


@api_router.get("/samples")
async def samples():
    return {
        "samples": [
            {
                "label": "High-Risk (Bank Phishing)",
                "risk": "high",
                "text": "URGENT! Your HDFC bank account will be BLOCKED today due to suspicious activity. Verify your account IMMEDIATELY by clicking http://hdfc-secure-verify.tk/login and entering your OTP and CVV. Do not share this message with anyone.",
            },
            {
                "label": "High-Risk (Prize Scam)",
                "risk": "high",
                "text": "Congratulations! You have WON a lottery of $500,000 in the Microsoft Annual Draw. To claim your prize, send your Aadhaar number, bank account details and a processing fee of $50 via Bitcoin to the wallet address in this link: bit.ly/claim-prize-now",
            },
            {
                "label": "Medium-Risk (Delivery Scam)",
                "risk": "medium",
                "text": "Your FedEx package delivery could not be completed due to an incorrect address. Please confirm your delivery information within 24 hours using the link below: http://fedex-redelivery.click/update",
            },
            {
                "label": "Safe (Legitimate Appointment)",
                "risk": "safe",
                "text": "Hi Priya, your appointment with ABC Clinic is confirmed for Monday at 10:30 AM. Please arrive 10 minutes early. Reply RESCHEDULE if you need to change the time.",
            },
            {
                "label": "Safe (Order Confirmation)",
                "risk": "safe",
                "text": "Thanks for your order #48213 - it has shipped and should arrive by Friday. You can track it at https://www.amazon.com/orders. No action needed.",
            },
        ]
    }


app.include_router(api_router)

cors_origins = [origin.strip().rstrip("/") for origin in os.environ.get("CORS_ORIGINS", "*").split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
