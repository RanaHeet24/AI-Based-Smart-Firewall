import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.predict_url import predict_url
from src.domain_reputation import get_domain_reputation
from src.heuristics import get_heuristic_score
from src.content_analyzer import analyze_html_content
from src.piracy_detector import detect_piracy_and_malware
from src.content_security_analyzer import analyze_content_security
from utils.logger import setup_logger

logger = setup_logger("RiskEngine", "risk_engine.log")

class RiskDecision:
    def __init__(self, final_score, decision, details):
        self.final_score = final_score
        self.decision = decision
        self.details = details

def get_ai_risk_score(url: str) -> float:
    """Wraps the AI prediction into a continuous probability/risk score."""
    # Our current RandomForest predict_url returns "SAFE" or "MALICIOUS"
    # To map to risk: MALICIOUS = 0.9, SAFE = 0.1
    # Note: If predict_proba was implemented, we could pass the exact probability.
    prediction = predict_url(url)
    if prediction == "MALICIOUS":
         return 0.90
    elif prediction == "SAFE":
         return 0.10
    else:
         # Model error
         return 0.50

def analyze_traffic_risk(url: str) -> RiskDecision:
    """
    Modular Multi-Layer Risk Scoring Engine.
    Combines AI, Reputation, Heuristics, Content Analysis, and Piracy into a final weighted score.
    """
    logger.info(f"Analyzing multi-layer risk for: {url}")
    
    # 1. AI Phishing Model Layer (Weight: 30%)
    ai_score = get_ai_risk_score(url)
    
    # 2. Domain Reputation Layer (Weight: 10%)
    reputation_score = get_domain_reputation(url)
    
    # 3. Heuristics Security Layer (Weight: 15%)
    heuristic_score = get_heuristic_score(url)
    
    # 4. HTML Content Analysis Layer (Weight: 15%)
    content_score = analyze_html_content(url)
    
    # 5. Piracy & Malware Detection Layer (Weight: 15%)
    piracy_result = detect_piracy_and_malware(url)
    piracy_score = piracy_result["risk_score"]
    
    # 6. Malware UI / Malvertising Content Layer (Weight: 15%)
    ui_sec_result = analyze_content_security(url)
    ui_sec_score = ui_sec_result["risk_score"]
    
    # Aggregate comprehensive explainable reasons
    reasons = []
    if ai_score > 0.6:
        reasons.append(f"AI phishing probability: {ai_score:.2f}")
    if reputation_score > 0.4:
        reasons.append("suspicious domain pattern or age")
    if heuristic_score > 0.4:
        reasons.append("suspicious URL heuristics (length/keywords)")
    if content_score > 0.3:
        reasons.append("malicious HTML content detected (e.g. login form)")
        
    for r in piracy_result.get("reasons", []):
        reasons.append(r)
    for r in ui_sec_result.get("reasons", []):
        reasons.append(r)
    
    # Calculate baseline weighted average
    weighted_risk_score = (ai_score * 0.30) + (reputation_score * 0.10) + (heuristic_score * 0.15) + (content_score * 0.15) + (piracy_score * 0.15) + (ui_sec_score * 0.15)
    
    # High Severity Override: Prevent Score Dilution
    # If a specific security model flags a severe threat, don't let safe heuristics dilute it to ALLOW.
    max_specific_threat = max(ai_score, piracy_score, ui_sec_score, content_score)
    
    # Final risk score becomes either the weighted average, or 95% of the highest unique threat detected.
    final_risk_score = max(weighted_risk_score, max_specific_threat * 0.95)
    
    # Categorize the website
    category = "SAFE"
    if final_risk_score > 0.4:
        if piracy_score > max(ai_score, ui_sec_score, content_score):
            category = "PIRACY"
        elif ui_sec_score > max(ai_score, piracy_score, content_score) or content_score > 0.5:
            category = "MALWARE"
        elif ai_score > max(ui_sec_score, piracy_score, content_score):
            category = "PHISHING"
        else:
            category = "SUSPICIOUS"
    
    # Decision Matrix
    if final_risk_score >= 0.70:
        decision = "BLOCK"
    elif final_risk_score >= 0.40:
        decision = "WARN"
    else:
        decision = "ALLOW"
        
    details = {
        "Category": category,
        "Reasons": reasons,
        "AI_Score": round(ai_score, 2),
        "Domain_Reputation": round(reputation_score, 2),
        "Heuristics": round(heuristic_score, 2),
        "HTML_Content": round(content_score, 2),
        "Piracy_Score": round(piracy_score, 2),
        "Piracy_Reasons": piracy_result["reasons"],
        "Malware_UI_Score": round(ui_sec_score, 2),
        "Malware_UI_Reasons": ui_sec_result["reasons"]
    }
    
    logger.info(f"Risk: {final_risk_score:.2f} | Decision: {decision} | Details: {details}")
    return RiskDecision(final_risk_score, decision, details)
