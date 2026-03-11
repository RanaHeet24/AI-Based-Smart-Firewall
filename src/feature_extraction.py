import re
from urllib.parse import urlparse

def extract_features(url: str) -> list:
    """
    Extracts features from a given URL for phishing detection.
    
    Features extracted in order:
    1. URL length
    2. Number of dots
    3. Number of subdomains
    4. Presence of IP address in URL (1 if yes, 0 if no)
    5. Number of special characters
    6. Presence of HTTPS (1 if yes, 0 if no)
    7. Number of digits in domain
    8. Suspicious keywords count ('login', 'secure', 'account', 'verify')
    
    Returns:
        list: A numerical vector of features.
    """
    # 1. URL length
    url_length = len(url)
    
    # 2. Number of dots
    num_dots = url.count('.')
    
    # Try to parse the URL
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        # Fallback if the URL doesn't have a valid scheme
        parsed_url = urlparse('http://' + url)
        
    domain = parsed_url.netloc

    # 3. Number of subdomains
    # A simple heuristic: count the dots in the domain. 
    # Example: www.google.com has 2 dots, so usually 1 subdomain + main domain + TLD.
    # If dots > 1, we assume (dots - 1) subdomains (ignoring complex ccTLDs to keep it simple).
    domain_dots = domain.count('.')
    num_subdomains = domain_dots - 1 if domain_dots > 1 else 0
    if domain.startswith("www."):
        num_subdomains = max(0, num_subdomains - 1) # Generally 'www' is ignored as a malicious subdomain

    # 4. Presence of IP address in URL
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    has_ip = 1 if ip_pattern.search(domain) else 0

    # 5. Number of special characters
    special_characters = ['@', '?', '-', '=', '_', '~', '%', '*', '&', '#', '+', '$', '!']
    num_special_chars = sum(url.count(char) for char in special_characters)

    # 6. Presence of HTTPS
    has_https = 1 if url.startswith('https://') else 0

    # 7. Number of digits in domain
    num_digits_in_domain = sum(c.isdigit() for c in domain)

    # 8. Suspicious keywords count ('login', 'secure', 'account', 'verify')
    suspicious_keywords = ['login', 'secure', 'account', 'verify', 'update', 'banking']
    lower_url = url.lower()
    suspicious_keywords_count = sum(lower_url.count(keyword) for keyword in suspicious_keywords)

    features = [
        url_length,
        num_dots,
        num_subdomains,
        has_ip,
        num_special_chars,
        has_https,
        num_digits_in_domain,
        suspicious_keywords_count
    ]

    return features

if __name__ == "__main__":
    # Test cases
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "https://secure-update-account.paypal.com.xyz",
        "http://suspicious-domain-123.com/verify?user=admin"
    ]
    for test_url in test_urls:
        print(f"URL: {test_url}")
        print(f"Features: {extract_features(test_url)}\n")
