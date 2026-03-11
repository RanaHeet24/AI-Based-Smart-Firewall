import tldextract

def get_heuristic_score(url: str) -> float:
    """
    Applies static heuristic rules to calculate a risk score.
    Returns a score between 0.0 (Safe) and 1.0 (High Risk).
    """
    risk_score = 0.0
    url_lower = url.lower()
    
    # 1. URL Length Threshold
    if len(url) > 75:
        risk_score += 0.3
    elif len(url) > 50:
        risk_score += 0.1
        
    # 2. Subdomain anomalies
    ext = tldextract.extract(url)
    if ext.subdomain:
        subdomain_count = len(ext.subdomain.split('.'))
        if subdomain_count >= 4:
             risk_score += 0.4
        elif subdomain_count == 3:
             risk_score += 0.2
             
    # 3. Suspicious Keywords (Phishing context)
    suspicious_keywords = [
        'login', 'verify', 'secure', 'account', 'update', 
        'banking', 'auth', 'confirm', 'wallet', 'password'
    ]
    keyword_matches = sum(1 for kw in suspicious_keywords if kw in url_lower)
    if keyword_matches >= 2:
        risk_score += 0.5
    elif keyword_matches == 1:
        risk_score += 0.2
        
    # 4. Too many special characters (obfuscation)
    special_chars = ['@', '-', '_', '=', '?', '%', '&', '*']
    char_count = sum(url.count(c) for c in special_chars)
    if char_count > 8:
        risk_score += 0.3
    elif char_count > 4:
        risk_score += 0.1
        
    # Cap at 1.0
    return min(1.0, risk_score)
