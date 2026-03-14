import tldextract

# Domains that are strictly safe and should NEVER trigger false positives
SAFE_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk",
    "github.com", "github.io",
    "youtube.com",
    "wikipedia.org",
    "stackoverflow.com",
    "microsoft.com", "live.com", "office.com", "outlook.com",
    "amazon.com", "amazon.in",
    "linkedin.com",
    "twitter.com", "x.com",
    "facebook.com", "instagram.com",
    "reddit.com",
    "apple.com",
    "yahoo.com",
    "bbc.com", "bbc.co.uk",
    "cnn.com", "nytimes.com",
    "cloudflare.com",
    "streamlit.io", "streamlit.app",
    "openai.com", "anthropic.com",
    "npmjs.com", "pypi.org", "python.org",
    "chatgpt.com", "phishtank.com", "crunchyroll.com"
}

def _get_registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

def is_safe_domain(url: str) -> bool:
    rd = _get_registered_domain(url)
    return rd in SAFE_DOMAINS

def get_heuristic_score(url: str) -> float:
    """
    Applies calibrated static heuristic rules to detect evasive/malicious URLs dynamically.
    Combines length, subdomain complexity, and malicious keyword stacking.
    """
    if is_safe_domain(url):
        return 0.0

    risk_score = 0.0
    url_lower = url.lower()
    ext = tldextract.extract(url)
    domain_full = f"{ext.domain}.{ext.suffix}".lower()
    
    # ── 1. Suspicious Keywords (Phishing & Piracy) ──
    # Aggressively scoring combinations of high-risk words in the domain vs path
    # Added common streaming/piracy terms to domain check
    high_risk_domain_keywords = ['login', 'secure', 'verify', 'update', 'account', 'auth', 'repack', 'freemovies', 'crack', 'movies', 'hd', 'stream']
    domain_matches = sum(1 for kw in high_risk_domain_keywords if kw in domain_full)
    
    if domain_matches >= 2:
        risk_score += 0.50 # Extremely suspicious: "secure-login-update.com" or "vegamovies"
    elif domain_matches == 1:
        risk_score += 0.25 # E.g., "fitgirl-repacks.site"

    path_keywords = ['password', 'signin', 'webscr', 'wallet', 'confirm', 'torrent', 'download', 'watch-free', '1080p', 'hindi-dubbed', 'dual-audio']
    path_matches = sum(1 for kw in path_keywords if kw in url_lower)
    
    if path_matches >= 3:
        risk_score += 0.35
    elif path_matches == 2:
        risk_score += 0.20
    elif path_matches == 1:
        risk_score += 0.08

    # ── 2. URL Length ──
    if len(url) > 150:
        risk_score += 0.25
    elif len(url) > 100:
        risk_score += 0.10

    # ── 3. Subdomain Depth ──
    if ext.subdomain:
        parts = [p for p in ext.subdomain.split('.') if p and p != 'www']
        depth = len(parts)
        if depth >= 4:
            risk_score += 0.40
        elif depth == 3:
            risk_score += 0.20

    # ── 4. IP address instead of domain name ──
    import re
    if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        risk_score += 0.55

    # ── 5. @ symbol obfuscation ──
    if '@' in url:
        risk_score += 0.60

    # ── 6. Special character overload ──
    special_chars = ['-', '=', '%', '&', '*', '_']
    if domain_full.count('-') >= 2:
        risk_score += 0.20 # E.g., fitgirl-repacks.site
        
    char_count = sum(url.count(c) for c in special_chars)
    if char_count > 15:
        risk_score += 0.15

    return min(1.0, risk_score)
