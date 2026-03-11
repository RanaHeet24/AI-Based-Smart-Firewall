import os
import joblib
from src.feature_extraction import extract_features
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import setup_logger
from utils.url_utils import sanitize_url

logger = setup_logger("Predictor", "predictor.log")

class URLPredictor:
    """Singleton-like class for loading and predicting to optimize memory/speed."""
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(URLPredictor, cls).__new__(cls)
            cls._instance.model = None
            cls._instance._load_model()
        return cls._instance

    def _load_model(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, "models", "phishing_detection_model.pkl")
        
        if not os.path.exists(model_path):
            logger.error(f"Model not found at: {model_path}. Run train_model.py FIRST.")
            self.model = None
            return
            
        try:
            self.model = joblib.load(model_path)
            logger.info("Successfully loaded Random Forest Model.")
        except Exception as e:
            import traceback
            logger.error(f"Exception while loading model: {e}")
            logger.error(traceback.format_exc())
            self.model = None

    def predict(self, url: str) -> str:
        if self.model is None:
            logger.error("Prediction attempted, but model is not loaded.")
            return "ERROR: MODEL_NOT_LOADED"

        try:
            sanitized_url = sanitize_url(url)
            features = extract_features(sanitized_url)
            
            # predict() returns an array, we take first element
            prediction = self.model.predict([features])[0]
            
            # 1 = Safe/Legitimate, 0 = Malicious
            result = "SAFE" if prediction == 1 else "MALICIOUS"
            logger.debug(f"Analyzed {sanitized_url} -> {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error during prediction for URL {url}: {e}")
            return "ERROR: PREDICTION_FAILED"

# Expose a functional interface for backwards compatibility
_predictor = None

def predict_url(url: str) -> str:
    global _predictor
    if _predictor is None:
        _predictor = URLPredictor()
    return _predictor.predict(url)
