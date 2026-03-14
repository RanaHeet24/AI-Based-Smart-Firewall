import requests
from bs4 import BeautifulSoup
import sys, os
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import setup_logger

logger = setup_logger("PiracyDetector", "piracy_detection.log")

# URL-level piracy signals
PIRACY_URL_KEYWORDS = [
    'crack', 'torrent', 'keygen', 'warez', 'repack',
    'pirate', 'nulled', 'darkwarez', 'cracked',
    'free-download', 'full-version', 'crack-download',
    'torrent-download', 'software-repack', 'freemovies',
    'mod-apk', 'modapk', 'apkpure-cracked', 'unblocked',
    'watch-free', 'streaming', 'hd-movies', '1080p-download'
]

# Suspicious file extensions commonly distributed by piracy/malware sites
SUSPICIOUS_EXTS = ('.exe', '.apk', '.scr', '.bat', '.torrent', '.iso', '.mkv', '.mp4', '.zip', '.rar')
MAGNET_PREFIX = 'magnet:?xt=urn:'
MIN_SUSPICIOUS_LINKS = 2

def detect_piracy_and_malware(url: str, html_content: str = None) -> dict:
    """
    Detects piracy and malware distribution dynamically based on URL keywords
    and the presence of suspicious download links in the HTML.
    """
    risk_score = 0.0
    reasons = []
    url_lower = url.lower()
    parsed_url = urlparse(url_lower)

    # ── 1. URL keyword scan ──
    # Check both the domain and the path for piracy-related keywords
    full_path_to_check = parsed_url.netloc + parsed_url.path
    matched_keywords = [kw for kw in PIRACY_URL_KEYWORDS if kw in full_path_to_check]
    
    if matched_keywords:
        # Each keyword adds 0.25, capped at 0.60 to avoid false positives purely on URL
        score_add = min(0.60, len(matched_keywords) * 0.25)
        risk_score += score_add
        reasons.append(f"Piracy keyword(s) detected: {', '.join(matched_keywords[:3])}")

    # ── 2. HTML deep analysis for actual malicious/piracy links ──
    # We only analyze if there's already some suspicion or if it's passed from the central engine
    if html_content:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = soup.find_all(['a', 'button'], href=True)
            
            suspicious_links = []
            for link in links:
                href = link.get('href', '').lower()
                text = link.get_text().lower()
                
                # Check for magnet links or suspicious direct file extensions
                if href.startswith(MAGNET_PREFIX) or any(href.endswith(ext) for ext in SUSPICIOUS_EXTS):
                    suspicious_links.append(href)
                # Check for buttons/links that aggressively say "download" alongside piracy terms
                elif 'download' in text and any(kw in text for kw in ['torrent', 'magnet', 'crack', 'free', 'hd']):
                    suspicious_links.append(href)

            if len(suspicious_links) >= MIN_SUSPICIOUS_LINKS:
                # Strong signal: actual distribution of suspicious files/magnets found
                risk_score += 0.50
                reasons.append(f"{len(suspicious_links)} suspicious download/torrent links detected")
                
            # Detect heavy use of obfuscated or external iframes (common in streaming/piracy)
            iframes = soup.find_all('iframe')
            external_iframes = 0
            for iframe in iframes:
                src = iframe.get('src', '')
                if src and src.startswith('http') and parsed_url.netloc not in src:
                    external_iframes += 1
            
            if external_iframes >= 4:
                risk_score += 0.20
                reasons.append("High number of external iframes (common in illegal streaming)")

        except Exception as e:
            logger.debug(f"HTML parsing error in piracy detector: {e}")

    final_score = min(1.0, risk_score)
    if final_score > 0:
        logger.info(f"Dynamic Piracy risk {final_score:.2f} for {url} | {reasons}")

    return {"risk_score": final_score, "reasons": reasons}
