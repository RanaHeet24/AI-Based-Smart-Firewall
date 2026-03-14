from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.risk_engine import analyze_traffic_risk
from utils.logger import setup_logger

app = Flask(__name__)
CORS(app)  # Allow extension to call this API
logger = setup_logger("APIServer", "api_server.log")


@app.route("/check-url", methods=["POST"])
def analyze_url():
    """
    Main API endpoint for the browser extension.
    Accepts: {"url": "https://example.com"}
    Returns: {"decision": "ALLOW|WARN|BLOCK", "score": 0.45, "category": "...", "reasons": [...]}
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"]
    
    try:
        # Run the full parallel multi-layer analysis
        result = analyze_traffic_risk(url)
        
        response = {
            "decision": result.decision,
            "score": round(result.final_score, 4),
            "category": result.category,
            "reasons": result.reasons
        }
        
        logger.info(f"API result for {url}: {result.decision} (score {result.final_score:.4f})")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing {url}: {str(e)}")
        return jsonify({
            "decision": "ALLOW",
            "score": 0.0,
            "category": "ERROR",
            "reasons": ["Analysis failed due to internal error"]
        }), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    # Render provides the PORT as an environment variable
    port = int(os.environ.get("PORT", 5000))
    # Must listen on 0.0.0.0 for Render to detect the port
    app.run(host="0.0.0.0", port=port, debug=False)
