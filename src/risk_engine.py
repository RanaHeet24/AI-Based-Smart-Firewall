import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.predict_url import predict_url_proba
from utils.logger import setup_logger

logger = setup_logger("RiskEngine", "risk_engine.log")

SAFE_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk",
    "github.com", "github.io",
    "youtube.com",
    "wikipedia.org",
    "stackoverflow.com",
    "amazon.com", "amazon.in",
    "microsoft.com", "live.com", "office.com", "outlook.com"
}

PIRACY_KEYWORDS = ['crack', 'torrent', 'repack', 'keygen', 'warez']
MALWARE_EXTENSIONS = ['.exe', '.apk', '.scr', '.zip']

class RiskDecision:
    def __init__(self, final_score: float, decision: str, category: str, reasons: list):
        self.final_score = final_score
        self.decision = decision
        self.category = category
        self.reasons = reasons

def get_registered_domain(url: str) -> str:
    try:
        import tldextract
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        return ""

def analyze_traffic_risk(url: str) -> RiskDecision:
    """
    Simple rule-based + ML hybrid decision pipeline.
    """
    logger.info(f"Analyzing: {url}")
    url_lower = url.lower()
    
    # 1. Check Safe domain whitelist
    domain = get_registered_domain(url)
    if domain in SAFE_DOMAINS:
        logger.info(f"Safe domain whitelist matched: {url}")
        return RiskDecision(0.0, "ALLOW", "SAFE", ["Safe domain whitelist matched"])

    # 2. Extract ML phishing probability
    try:
        phishing_probability = predict_url_proba(url)
    except Exception as e:
        logger.error(f"Error predicting ML score for {url}: {str(e)}")
        phishing_probability = 0.0
        
    logger.info(f"ML Phishing Probability for {url}: {phishing_probability}")

    # 3. Rule-based checks
    decision = "ALLOW"
    category = "SAFE"
    reasons = []
    score = phishing_probability

    if phishing_probability > 0.7:
        decision = "BLOCK"
        category = "PHISHING"
        reasons.append(f"High AI phishing probability ({phishing_probability:.2f})")
        score = max(score, 0.85)

    if any(kw in url_lower for kw in PIRACY_KEYWORDS):
        decision = "BLOCK"
        if category == "SAFE": category = "PIRACY"
        reasons.append("Piracy keywords detected in URL")
        score = max(score, 0.82)

    if any(ext in url_lower for ext in MALWARE_EXTENSIONS):
        decision = "BLOCK"
        if category == "SAFE": category = "MALWARE"
        reasons.append("Suspicious executable download patterns detected")
        score = max(score, 0.90)

    if len(url) > 150 or url_lower.count('-') > 4:
        decision = "BLOCK"
        if category == "SAFE": category = "SUSPICIOUS"
        reasons.append("Highly suspicious/evasive domain structure")
        score = max(score, 0.75)

    if decision == "ALLOW":
        reasons.append("No malicious indicators detected")
        score = min(score, 0.4) # Ensure score reflects ALLOW status

    logger.info(f"Decision for {url}: {decision} (Score: {score})")
    return RiskDecision(score, decision, category, reasons)
