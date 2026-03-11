import requests
from bs4 import BeautifulSoup
from utils.logger import setup_logger

logger = setup_logger("ContentAnalyzer", "content_analysis.log")

def analyze_html_content(url: str) -> float:
    """
    Fetches the webpage HTML and analyzes it for phishing indicators.
    Returns a content risk score between 0.0 (Safe) and 1.0 (High Risk).
    """
    risk_score = 0.0
    
    try:
        # Fetch HTML safely with a strict timeout so the firewall doesn't hang
        # Using a generic User-Agent to avoid simple bot blocks
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=5)
        
        # If the page doesn't exist or returns an error, we can't analyze content.
        # But a 404 isn't inherently a phishing attack, so we just return 0.0
        if response.status_code != 200:
            return 0.0
            
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Detect Password Input Fields
        password_inputs = soup.find_all('input', type='password')
        if password_inputs:
            logger.info(f"Detected {len(password_inputs)} password field(s) on {url}")
            risk_score += 0.4
            
        # 2. Detect Login Forms (Form action pointing elsewhere or obvious login classes)
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '').lower()
            if 'login' in action or 'auth' in action or 'sign-in' in action:
                risk_score += 0.2
        
        # 3. Hidden Elements (Often used by malware/phishing to hide text or links)
        hidden_elements = soup.find_all(style=lambda value: value and ('display:none' in value.replace(' ', '') or 'display: none' in value.replace(' ', '')))
        if len(hidden_elements) > 5:
            risk_score += 0.2
            
        # 4. Suspicious iFrames (Often used to inject external malicious content)
        iframes = soup.find_all('iframe')
        suspicious_iframes = 0
        for iframe in iframes:
            src = iframe.get('src', '')
            # If the iframe points to a totally different domain or has no source but has sizing
            if src and not src.startswith('/') and not src.startswith(url):
                suspicious_iframes += 1
                
        if suspicious_iframes >= 2:
            risk_score += 0.3
            
        # 5. Suspicious Title Keywords
        title = soup.title.string.lower() if soup.title and soup.title.string else ""
        suspicious_titles = ['login', 'verify', 'update account', 'security check', 'wallet']
        if any(keyword in title for keyword in suspicious_titles):
            risk_score += 0.3
            
        return min(1.0, risk_score)
        
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout while fetching content for analysis: {url}")
        return 0.2  # Slight risk for timeout (could be an evasive tactic)
    except Exception as e:
        logger.error(f"Error analyzing content for {url}: {e}")
        return 0.1  # Minimal penalty on error to prevent breaking the firewall
