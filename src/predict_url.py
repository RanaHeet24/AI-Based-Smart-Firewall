import os
import sys
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.feature_extraction import extract_features
from utils.logger import setup_logger
from utils.url_utils import sanitize_url

logger = setup_logger("Predictor", "predictor.log")


class URLPredictor:
    """Singleton for loading and predicting; uses predict_proba when available."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance.model = None
            cls._instance._load_model()
        return cls._instance

    def _load_model(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, "models", "phishing_detection_model.pkl")
        if not os.path.exists(model_path):
            logger.error(f"Model not found at: {model_path}. Run train_model.py first.")
            self.model = None
            return
        try:
            self.model = joblib.load(model_path)
            logger.info("Successfully loaded Random Forest model.")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = None

    def predict_proba(self, url: str) -> float:
        """
        Returns phishing probability as a float in [0.0, 1.0].
        Higher value = more likely malicious.
        Uses predict_proba() when available; falls back to binary prediction.
        """
        if self.model is None:
            logger.warning("Model not loaded — returning neutral score 0.30")
            return 0.30

        try:
            sanitized = sanitize_url(url)
            features = extract_features(sanitized)

            # Use probability output if the model supports it (most sklearn estimators do)
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba([features])[0]
                # Class 0 = Malicious, Class 1 = Safe
                # proba[0] = P(malicious), proba[1] = P(safe)
                # Return malicious probability
                classes = list(self.model.classes_)
                if 0 in classes:
                    malicious_prob = proba[classes.index(0)]
                else:
                    # Binary where 1=MALICIOUS
                    malicious_prob = proba[-1]
                logger.debug(f"{sanitized} → phishing_prob={malicious_prob:.3f}")
                return float(malicious_prob)
            else:
                # Hard binary fallback
                pred = self.model.predict([features])[0]
                # 1 = Safe/Legitimate, 0 = Malicious
                result = 0.15 if pred == 1 else 0.85
                logger.debug(f"{sanitized} → binary fallback={result}")
                return result

        except Exception as e:
            logger.error(f"Prediction error for {url}: {e}")
            return 0.30   # neutral — don't block on error


# ── Module-level functional interface ─────────────────────────────────────────
_predictor = None


def predict_url(url: str) -> str:
    """Legacy interface — returns 'SAFE' or 'MALICIOUS'."""
    global _predictor
    if _predictor is None:
        _predictor = URLPredictor()
    prob = _predictor.predict_proba(url)
    return "MALICIOUS" if prob >= 0.5 else "SAFE"


def predict_url_proba(url: str) -> float:
    """Returns phishing probability in [0.0, 1.0]."""
    global _predictor
    if _predictor is None:
        _predictor = URLPredictor()
    return _predictor.predict_proba(url)
