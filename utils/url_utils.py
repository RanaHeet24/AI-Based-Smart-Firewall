from urllib.parse import urlparse
import re

def is_valid_url(url: str) -> bool:
    """
    Validates if the provided string is a well-formed URL.
    """
    try:
        result = urlparse(url)
        # Accept http, https, and cases where only the domain is provided
        return all([result.scheme in ['http', 'https', ''], result.netloc or result.path])
    except Exception:
        return False

def sanitize_url(url: str) -> str:
    """
    Sanitizes the URL. Ensures it has a proper scheme for analysis and routing.
    Strips leading/trailing whitespaces.
    """
    url = url.strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        # Default to http for analysis and proxy forwarding unless specified
        url = 'http://' + url
    return url
