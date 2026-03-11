import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from utils.logger import setup_logger

logger = setup_logger("ContentSecurityAnalyzer", "content_security.log")

def analyze_content_security(url: str, html_content: str = None) -> dict:
    """
    Analyzes HTML content for fake download buttons, redirected downloads,
    malvertising, and drive-by downloads.
    """
    risk_score = 0.0
    reasons = []
    
    # 1. Fetch HTML if not manually provided
    if html_content is None:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                html_content = response.text
            else:
                html_content = ""
        except Exception as e:
            logger.warning(f"Failed to fetch HTML for {url}: {e}")
            html_content = ""
            
    if not html_content:
        return {"category": "SAFE", "risk_score": 0.0, "reasons": []}
        
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 1. Fake Download Button Detection
    download_buttons = 0
    # Look for button tags or anchor tags styled as buttons that say download
    elements = soup.find_all(['button', 'a'])
    for el in elements:
        text = el.get_text().lower()
        if 'download' in text:
            if 'now' in text or 'fast' in text or 'mirror' in text or 'direct' in text:
                download_buttons += 1
            elif el.name == 'button':
                download_buttons += 1
                
    if download_buttons > 2:
        risk_score += 0.3
        reasons.append("multiple fake download buttons detected")
        
    # 2. Redirected Download Links / Executable Download Detection
    suspicious_extensions = ['.exe', '.apk', '.rar', '.zip', '.iso', '.scr']
    exe_link_found = False
    for link in soup.find_all('a', href=True):
        href = link.get('href', '').lower()
        if any(ext in href for ext in suspicious_extensions) or any(f"{ext}?" in href for ext in suspicious_extensions):
            exe_link_found = True
            break
            
    if exe_link_found:
        risk_score += 0.4
        reasons.append("executable download link found")
        
    # 3. Malvertising Detection
    # Detect external ad scripts or suspicious iframe advertisements
    ad_keywords = ['ads', 'advert', 'banner', 'tracking', 'pop', 'click', 'sponsor']
    suspicious_ad_found = False
    
    parsed_url = urlparse(url)
    
    # Check iframes
    for iframe in soup.find_all('iframe', src=True):
        src = iframe.get('src', '').lower()
        parsed_src = urlparse(src)
        # If iframe is from an external domain
        if parsed_src.netloc and parsed_src.netloc != parsed_url.netloc:
            if any(ad_kw in src for ad_kw in ad_keywords):
                suspicious_ad_found = True
                
    if suspicious_ad_found:
        risk_score += 0.2
        reasons.append("suspicious iframe advertisement")
        
    # 4. Drive-by Download Detection
    # Look for automated assignments in JS like window.location="malware.exe"
    driveby_pattern = r'window\.location\s*=\s*["\']([^"\']+\.(?:exe|apk|scr|zip|rar|iso))["\']'
    if re.search(driveby_pattern, html_content, re.IGNORECASE):
        risk_score += 0.5
        reasons.append("drive-by download script detected")
        
    # Look for hidden iframes attempting to trigger downloads
    hidden_iframes = soup.find_all('iframe', style=lambda value: value and ('display:none' in value.replace(' ', '') or 'visibility:hidden' in value.replace(' ', '')))
    for iframe in hidden_iframes:
        src = iframe.get('src', '').lower()
        if any(ext in src for ext in suspicious_extensions):
            risk_score += 0.5
            reasons.append("hidden iframe executable download detected")
            
    # Cap score at 1.0
    final_score = min(1.0, risk_score)
    category = "MALWARE" if final_score > 0.0 else "SAFE"
    
    result = {
        "category": category,
        "risk_score": final_score,
        "reasons": list(set(reasons))
    }
    
    if final_score > 0:
        logger.info(f"Malware Content risk for {url}: {final_score:.2f} | Reasons: {result['reasons']}")
        
    return result
