import os
from datetime import datetime
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.risk_engine import analyze_traffic_risk
from utils.logger import setup_logger

logger = setup_logger("FirewallEngine", "firewall_engine.log")

def log_firewall_action(url: str, decision: str, score: float, details: dict = None):
    """
    Logs firewall events to logs/firewall_events.jsonl for the dashboard.
    """
    import json
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logs_dir = os.path.join(base_dir, "logs")
    log_file_path = os.path.join(logs_dir, "firewall_events.jsonl")

    os.makedirs(logs_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    event = {
        "timestamp": timestamp,
        "url": url,
        "decision": decision,
        "risk_score": score,
        "details": details or {}
    }

    try:
        with open(log_file_path, "a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")
        logger.info(f"Recorded action: {decision} for {url}")
    except Exception as e:
        logger.error(f"Failed to record action for {url}: {e}")

def process_request(url: str):
    """
    Core AI Firewall Decision Logic using Multi-Layer Engine.
    Returns: {"decision": "ALLOW"|"WARN"|"BLOCK", "score": float, "details": dict}
    """
    try:
        risk_evaluation = analyze_traffic_risk(url)
        
        # Always log to JSONL for the dashboard analytics
        log_firewall_action(url, risk_evaluation.decision, risk_evaluation.final_score, risk_evaluation.details)
            
        return {
            "decision": risk_evaluation.decision,
            "score": risk_evaluation.final_score,
            "details": risk_evaluation.details
        }
            
    except Exception as e:
        logger.critical(f"Unhandled exception in firewall engine for {url}: {e}")
        # Assume hostile on system failure
        return {"decision": "BLOCK", "score": 1.0, "details": {}}
