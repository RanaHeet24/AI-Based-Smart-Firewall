import sys
import os
import requests
from flask import Flask, request, Response, render_template

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.firewall_engine import process_request
from utils.logger import setup_logger
from utils.url_utils import sanitize_url, is_valid_url

logger = setup_logger("ProxyServer", "proxy.log")

app = Flask(__name__)

# Basic landing page
@app.route('/')
def home():
    return "🚀 AI Smart Firewall Proxy Server is active and monitoring.", 200

# Using a catch-all route to act as a proxy
@app.route('/<path:url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(url):
    """
    Scalable Proxy interceptor. 
    Intercepts, analyzes, blocks or forwards the HTTP traffic based on AI Model.
    """
    target_url = sanitize_url(url)
    
    # If the request comes with query parameters, append them
    if request.query_string:
         target_url += '?' + request.query_string.decode('utf-8')

    if not is_valid_url(target_url):
         logger.warning(f"Invalid URL requested: {target_url}")
         return "<b>Firewall Error:</b> Invalid URL format.", 400

    logger.info(f"Intercepting request to -> {target_url}")

    # Firewall Engine Core Decision (Multi-Layer)
    decision_result = process_request(target_url)

    if decision_result.get("decision") == "BLOCK":
        logger.warning(f"Proxy responding with Access Denied for {target_url}")
        return _generate_block_screen(target_url, decision_result), 403
        
    elif decision_result.get("decision") == "WARN":
        logger.warning(f"Proxy responding with Security Warning for {target_url}")
        return _generate_warn_screen(target_url, decision_result), 403
    
    elif decision_result.get("decision") == "ALLOW":
        return _forward_request(target_url)

    # Failsafe
    return "Unknown Firewall Error", 500

def _forward_request(target_url):
    """Handles the actual proxy forwarding to external servers safely."""
    try:
        # Exclude 'Host' header to let requests set it properly for the target server
        headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
        
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10 # Prevent hanging on malicious/slow servers
        )
        
        # Create a Flask response mimicking the actual server's response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                        if name.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, resp_headers)
        
    except requests.exceptions.Timeout:
         logger.error(f"Timeout while forwarding to {target_url}")
         return f"<b>Proxy Error:</b> Timeout connecting to {target_url}.", 504
    except requests.exceptions.RequestException as e:
         logger.error(f"Request exception forwarding to {target_url}: {e}")
         return f"<b>Proxy Error:</b> Could not reach {target_url}.", 502

def _generate_block_screen(target_url, details):
    """Returns the standardized HTML for blocked pages."""
    risk_score = details.get("score", 1.0)
    ai_score = details.get("details", {}).get("AI_Score", "N/A")
    rep_score = details.get("details", {}).get("Domain_Reputation", "N/A")
    heur_score = details.get("details", {}).get("Heuristics", "N/A")
    
    return f"""
    <html>
        <head>
            <title>Access Denied - AI Smart Firewall</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; text-align: center; margin-top: 80px; background-color: #fafafa; color: #333; }}
                .container {{ max-width: 650px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; border-top: 6px solid #d32f2f; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }}
                .warning-icon {{ color: #d32f2f; font-size: 80px; margin-bottom: 10px; line-height: 1; }}
                h1 {{ color: #d32f2f; font-size: 38px; margin: 0 0 10px 0; }}
                h2 {{ color: #666; font-size: 20px; font-weight: 500; margin-top: 0; }}
                p {{ font-size: 16px; line-height: 1.6; color: #555; margin-top: 25px; }}
                .url-box {{ background-color: #fce4e4; padding: 15px; border-radius: 6px; margin: 20px 0; }}
                .url {{ font-family: 'Courier New', monospace; color: #c62828; word-break: break-all; font-weight: 600; font-size: 15px; }}
                .metrics {{ display: flex; justify-content: space-around; background: #fff3f3; padding: 15px; border-radius: 8px; margin-top: 20px; text-align: center; border: 1px solid #ffcdd2; }}
                .metric-item strong {{ display: block; font-size: 18px; color: #b71c1c; }}
                .metric-item span {{ font-size: 12px; color: #666; text-transform: uppercase; }}
                .footer {{ margin-top: 30px; font-size: 13px; color: #999; border-top: 1px solid #eee; padding-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="warning-icon">⛔</div>
                <h1>Access Denied</h1>
                <h2>Request Blocked by Security Policies</h2>
                <div class="url-box">
                    <span class="url">{target_url}</span>
                </div>
                <p>The Multi-Layer Intelligence Engine has analyzed this destination and classified it as a severe threat with a Critical Risk Score ({risk_score:.2f}).</p>
                <div class="metrics">
                    <div class="metric-item"><strong>{ai_score}</strong><span>AI Phishing Score</span></div>
                    <div class="metric-item"><strong>{rep_score}</strong><span>Domain Risk</span></div>
                    <div class="metric-item"><strong>{heur_score}</strong><span>Heuristics</span></div>
                </div>
                <div class="footer">AI Smart Firewall - Predictive Cyber Protection</div>
            </div>
        </body>
    </html>
    """
    
def _generate_warn_screen(target_url, details):
    """Returns an HTML warning page for medium-risk sites."""
    risk_score = details.get("score", 0.5)
    return f"""
    <html>
        <head>
            <title>Security Warning - AI Smart Firewall</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; text-align: center; margin-top: 80px; background-color: #fafafa; color: #333; }}
                .container {{ max-width: 650px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; border-top: 6px solid #f57c00; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }}
                .warning-icon {{ color: #f57c00; font-size: 80px; margin-bottom: 10px; line-height: 1; }}
                h1 {{ color: #f57c00; font-size: 38px; margin: 0 0 10px 0; }}
                h2 {{ color: #666; font-size: 20px; font-weight: 500; margin-top: 0; }}
                p {{ font-size: 16px; line-height: 1.6; color: #555; margin-top: 25px; }}
                .url-box {{ background-color: #fff3e0; padding: 15px; border-radius: 6px; margin: 20px 0; border: 1px solid #ffe0b2;}}
                .url {{ font-family: 'Courier New', monospace; color: #e65100; word-break: break-all; font-weight: 600; font-size: 15px; }}
                .footer {{ margin-top: 30px; font-size: 13px; color: #999; border-top: 1px solid #eee; padding-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="warning-icon">⚠</div>
                <h1>Security Warning</h1>
                <h2>Suspicious Destination Detected</h2>
                <div class="url-box">
                    <span class="url">{target_url}</span>
                </div>
                <p>The AI Smart Firewall has flagged this traffic as potentially unsafe, showing an elevated Risk Score of {risk_score:.2f}. Proceed with extreme caution.</p>
                <div class="footer">AI Smart Firewall - Predictive Cyber Protection</div>
            </div>
        </body>
    </html>
    """

if __name__ == "__main__":
    logger.info("Initializing Flask Proxy Server Engine...")
    app.run(host="0.0.0.0", port=5000, threaded=True) # Threaded for concurrent scaling
