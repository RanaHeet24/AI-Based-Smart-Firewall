import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from utils.logger import setup_logger

logger = setup_logger("PiracyDetector", "piracy_detection.log")

def detect_piracy_and_malware(url: str, html_content: str = None) -> dict:
    """
    Detects websites that are likely distributing pirated software or malware.
    Returns a result dict with category, risk_score, and reasons.
    """
    risk_score = 0.0
    reasons = []
    
    url_lower = url.lower()
    
    # 1. Keyword Pattern Detection
    piracy_keywords = [
        'crack', 'torrent', 'repack', 'keygen', 
        'free download full version', 'mod apk', 'patched', 'warez'
    ]
    
    for kw in piracy_keywords:
        if kw in url_lower:
            risk_score += 0.3
            reasons.append(f"keyword '{kw}' detected")
            
    # 2. Piracy Domain Pattern Detection
    suspicious_domains = [
        'free-download', 'full-version', 'crack-download',
        'torrent-download', 'software-repack', 'repack'
    ]
    
    parsed_url = urlparse(url_lower)
    domain = parsed_url.netloc
    
    for pattern in suspicious_domains:
        if pattern in domain:
            risk_score += 0.4
            reasons.append(f"suspicious domain pattern '{pattern}' detected")
            
    # 3. Executable & Torrent Download Detection
    suspicious_extensions = ['.exe', '.apk', '.rar', '.zip', '.iso', '.scr', '.torrent']
    
    # Fetch HTML if not manually provided
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
            
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for executable, torrent, or magnet links
        exe_found = False
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '').lower()
            if href.startswith('magnet:?xt=urn:') or any(href.endswith(ext) for ext in suspicious_extensions) or any(f"{ext}?" in href for ext in suspicious_extensions):
                exe_found = True
                break
                
        if exe_found:
            risk_score += 0.5
            reasons.append("executable/torrent download detected")
            
    # Cap score at 1.0
    final_score = min(1.0, risk_score)
    category = "PIRACY" if final_score > 0.0 else "SAFE"
    
    result = {
        "category": category,
        "risk_score": final_score,
        "reasons": list(set(reasons))  # Remove duplicate reasons
    }
    
    if final_score > 0:
        logger.info(f"Piracy risk for {url}: {final_score:.2f} | Reasons: {result['reasons']}")
        
    return result
