import requests
from bs4 import BeautifulSoup
from utils.logger import setup_logger

logger = setup_logger("ContentAnalyzer", "content_analysis.log")


def analyze_html_content(url: str, html_content: str = None) -> float:
    """
    Analyzes HTML content for phishing indicators.
    Returns a content risk score between 0.0 (Safe) and 1.0 (High Risk).
    """
    if not html_content:
        return 0.0

    risk_score = 0.0

    try:
        soup = BeautifulSoup(html_content, 'html.parser')

        # ── 1. Password field + external form action (phishing combo) ──────────
        password_inputs = soup.find_all('input', {'type': 'password'})
        if password_inputs:
            forms = soup.find_all('form')
            external_action = False
            for form in forms:
                action = form.get('action', '')
                if action and action.startswith('http') and not _same_domain(url, action):
                    external_action = True
                    break
            if external_action:
                risk_score += 0.55
                logger.info(f"Password field + external form action on {url}")
            else:
                risk_score += 0.12

        # ── 2. Login form action keywords ─────────────────────────────────────
        for form in soup.find_all('form'):
            action = form.get('action', '').lower()
            if any(kw in action for kw in ('phish', 'steal', 'harvest')):
                risk_score += 0.40

        # ── 3. Excessive hidden elements (obfuscation) ────────────────────────
        hidden = soup.find_all(style=lambda v: v and 'display:none' in v.replace(' ', ''))
        if len(hidden) > 10:
            risk_score += 0.20
        elif len(hidden) > 5:
            risk_score += 0.08

        # ── 4. Suspicious external iFrames ────────────────────────────────────
        suspicious_iframes = 0
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            if src and src.startswith('http') and not _same_domain(url, src):
                suspicious_iframes += 1
        if suspicious_iframes >= 3:
            risk_score += 0.30
        elif suspicious_iframes >= 1:
            risk_score += 0.08

        # ── 5. Suspicious page title ──────────────────────────────────────────
        title = ''
        if soup.title and soup.title.string:
            title = soup.title.string.lower()
        if any(kw in title for kw in ('verify your account', 'security check', 'your wallet')):
            risk_score += 0.25

        return min(1.0, risk_score)

    except Exception as e:
        logger.error(f"Content analysis error for {url}: {e}")
        return 0.0


def _same_domain(base_url: str, target_url: str) -> bool:
    try:
        import tldextract
        b = tldextract.extract(base_url)
        t = tldextract.extract(target_url)
        return f"{b.domain}.{b.suffix}" == f"{t.domain}.{t.suffix}"
    except Exception:
        return False
