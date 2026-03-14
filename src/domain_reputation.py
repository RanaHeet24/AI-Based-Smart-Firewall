import tldextract
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import setup_logger

logger = setup_logger("DomainReputation", "reputation.log")

# High-risk TLDs that are disproportionately used for phishing/fraud
HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',   # free Freenom TLDs — massively abused
    'xyz', 'top', 'click', 'loan',    # statistically suspicious
    'work', 'vip', 'win', 'racing',
    'biz',                             # moderate risk
}

def get_domain_reputation(url: str) -> float:
    """
    Returns a domain risk score between 0.0 (Safe) and 1.0 (High Risk).
    Uses TLD analysis and optional WHOIS age checking.
    WHOIS failure/unavailability adds NO penalty (many legit domains block WHOIS).
    """
    ext = tldextract.extract(url)

    if not ext.domain or not ext.suffix:
        # Raw IP address or malformed — high risk
        return 0.70

    risk_score = 0.0
    suffix_lower = ext.suffix.lower()

    # 1. Suspicious TLD check (primary signal)
    if suffix_lower in HIGH_RISK_TLDS:
        risk_score += 0.45

    # 2. Domain Age via WHOIS (optional — failure adds ZERO penalty)
    try:
        import whois
        from datetime import datetime
        domain_name = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now() - creation_date).days
            if age_days < 7:
                risk_score += 0.45
            elif age_days < 30:
                risk_score += 0.25
            elif age_days < 90:
                risk_score += 0.10
        # If creation_date is None, we simply add nothing
    except Exception as e:
        # WHOIS failure is normal for many legitimate domains — no penalty!
        logger.debug(f"WHOIS unavailable for {ext.domain}.{ext.suffix}: {e}")

    return min(1.0, risk_score)
