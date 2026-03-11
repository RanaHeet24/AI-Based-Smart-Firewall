import whois
import tldextract
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("DomainReputation", "reputation.log")

def get_domain_reputation(url: str) -> float:
    """
    Checks the reputation of a domain using WHOIS age 
    and suspicious TLD patterns.
    
    Returns a risk score between 0.0 (Safe) and 1.0 (High Risk).
    """
    ext = tldextract.extract(url)
    domain_name = f"{ext.domain}.{ext.suffix}"
    
    if not ext.domain or not ext.suffix:
        # IP addresses or malformed domains inherently carry more risk
        return 0.8
        
    risk_score = 0.0
    
    # 1. Check suspicious TLDs
    suspicious_tlds = ['xyz', 'top', 'info', 'tk', 'ml', 'ga', 'cf', 'gq', 'online', 'vip', 'biz']
    if ext.suffix.lower() in suspicious_tlds:
        risk_score += 0.4
        
    # 2. Check Domain Age
    try:
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            age_days = (datetime.now() - creation_date).days
            
            # Domains newer than 30 days are highly suspicious
            if age_days < 30:
                risk_score += 0.5
            # Domains between 30 and 180 days are moderately suspicious
            elif age_days < 180:
                risk_score += 0.2
        else:
            # Cannot determine age - adds slight risk
            risk_score += 0.3
            
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain_name}: {e}")
        # WHOIS strictly rate limits or fails for some ccTLDs. 
        # Add a baseline risk if we can't verify.
        risk_score += 0.2
        
    # Cap score at 1.0
    return min(1.0, risk_score)
