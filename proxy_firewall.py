import os
import sys

# Add project root to path so we can import src modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser
from proxy.http.exception import HttpRequestRejected

# Import ML Risk Engine
from src.risk_engine import analyze_traffic_risk

class FirewallPlugin(HttpProxyBasePlugin):
    """
    AI Smart Firewall Plugin for proxy.py
    Intercepts proxy requests and blocks malicious/piracy sites.
    """

    def before_upstream_connection(self, request: HttpParser) -> HttpParser:
        # Extract URL host
        if not request.host:
            return request
            
        try:
            url = request.host.decode('utf-8')
        except AttributeError:
            url = str(request.host)

        print(f"\n[AI Firewall] Checking URL: {url}")

        # Skip scanning local connections
        if url in ("127.0.0.1", "localhost"):
            return request

        # -------------------------------
        # ML Model Integration
        # -------------------------------
        try:
            risk = analyze_traffic_risk(url)
            score = risk.final_risk_score
            category = risk.details.get("Category", "Unknown")
        except Exception as e:
            print(f"[!] Error in risk engine: {e}")
            score = 0
            category = "SAFE"
            
        print(f"[*] AI Risk Score: {score:.2f} | Category: {category}")

        # Check blocking conditions
        block_connection = False
        reason = ""

        # Condition 1: High risk from ML model (Phishing, Malware, Piracy)
        if score >= 0.7 or category in ("PIRACY", "MALWARE", "PHISHING", "BLOCK"):
            block_connection = True
            reason = f"Blocked by ML Security Layer ({category})"

        # Condition 2: Keyword-based blocking (e.g., piracy keywords)
        elif "repack" in url.lower() or "torrent" in url.lower():
            block_connection = True
            reason = "Blocked by Hardcoded Rules (Piracy Keyword)"
            score = 0.99
            category = "PIRACY"

        # Block the request
        if block_connection:
            print(f"[!] BLOCKED: {url} | Reason: {reason}")
            
            # Formulate the blocked HTML page
            html_content = f"""
            <html>
            <head>
                <title>Access Denied - AI Smart Firewall</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 50px; background-color: #1a1a1a; color: #fff; }}
                    h1 {{ color: #ff4d4d; font-size: 3em; margin-bottom: 10px; }}
                    .container {{ background: #2a2a2a; padding: 30px; border-radius: 12px; display: inline-block; text-align: left; box-shadow: 0 4px 15px rgba(0,0,0,0.5); border: 1px solid #ff4d4d; max-width: 600px; }}
                    h2 {{ color: #ff9999; margin-top: 0; }}
                    p {{ font-size: 1.1em; line-height: 1.5; }}
                    .footer {{ margin-top: 20px; font-size: 0.9em; color: #888; text-align: center; }}
                </style>
            </head>
            <body>
                <h1>Access Denied</h1>
                <div class="container">
                    <h2>Blocked by AI Smart Firewall</h2>
                    <p><strong>URL Target:</strong> {url}</p>
                    <p><strong>Risk Score:</strong> {score:.2f} (High Risk)</p>
                    <p><strong>Category:</strong> {category}</p>
                    <p><strong>Detection Detail:</strong> {reason}</p>
                </div>
                <div class="footer">
                    <p>Network traffic intercepted and blocked for security purposes.</p>
                </div>
            </body>
            </html>
            """
            
            # Raise exception to immediately reject and return 403 response
            raise HttpRequestRejected(
                status_code=403,
                reason=b"Forbidden",
                body=html_content.encode('utf-8'),
                headers={
                    b"Content-Type": b"text/html",
                    b"Connection": b"close"
                }
            )

        print(f"[+] ALLOWED: {url}")
        return request

    def handle_client_request(self, request: HttpParser) -> HttpParser:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
