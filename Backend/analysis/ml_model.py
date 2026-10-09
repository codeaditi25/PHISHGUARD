"""
LinkShield - Machine Learning Phishing Risk Classifier

Purpose:
    Provide an ML-based second-layer detection engine for phishing URLs.
    Extracts structural/lexical features using url_parser and evaluates
    them using a pre-trained RandomForestClassifier.
"""

from pathlib import Path
from typing import Union, Dict, Any, List
import joblib
import numpy as np

from .url_parser import (
    parse_url,
    count_subdomains,
    is_ip_address,
)

# Relative model path inside analysis/
MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"

# Feature list used during training & inference
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "subdomain_count",
    "is_ip",
    "is_https",
    "count_hyphens",
    "count_at",
    "count_dots",
    "count_slashes",
    "count_digits",
    "count_question",
    "count_equal",
    "has_suspicious_keyword",
    "is_shortener",
]

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "confirmation", "password",
    "signin", "sign-in", "banking", "wallet", "payment",
    "invoice", "credential", "recover", "unlock", "ebayisapi",
    "paypal", "appleid", "support",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
}


def extract_features(data: Union[dict, str]) -> List[float]:
    """
    Extract a normalized numerical feature vector from a URL or parsed dict.
    """
    if isinstance(data, str):
        parsed = parse_url(data)
    else:
        parsed = data

    url = parsed.get("normalized") or parsed.get("original") or ""
    hostname = parsed.get("hostname") or ""
    path = parsed.get("path") or ""
    scheme = parsed.get("scheme") or ""

    url_length = float(len(url))
    domain_length = float(len(hostname))
    path_length = float(len(path))
    subdomain_count = float(parsed.get("subdomain_count", count_subdomains(hostname)))
    is_ip = 1.0 if parsed.get("is_ip", is_ip_address(hostname)) else 0.0
    is_https = 1.0 if scheme == "https" else 0.0

    count_hyphens = float(hostname.count("-"))
    count_at = float(url.count("@"))
    count_dots = float(url.count("."))
    count_slashes = float(url.count("/"))
    count_digits = float(sum(c.isdigit() for c in url))
    count_question = float(url.count("?"))
    count_equal = float(url.count("="))

    url_lower = url.lower()
    has_keyword = 1.0 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0.0
    is_shortener = 1.0 if any(short in hostname.lower() for short in URL_SHORTENERS) else 0.0

    return [
        url_length,
        domain_length,
        path_length,
        subdomain_count,
        is_ip,
        is_https,
        count_hyphens,
        count_at,
        count_dots,
        count_slashes,
        count_digits,
        count_question,
        count_equal,
        has_keyword,
        is_shortener,
    ]


# Cache loaded model at module level
_MODEL = None


def load_model():
    """Load the trained machine learning model from disk."""
    global _MODEL
    if _MODEL is not None:
        return _MODEL

    if MODEL_PATH.exists():
        try:
            _MODEL = joblib.load(MODEL_PATH)
            return _MODEL
        except Exception as e:
            print(f"[LinkShield ML] Error loading model from {MODEL_PATH}: {e}")
            return None
    return None


def predict_ml_risk(parsed: dict) -> float:
    """
    Predict the phishing probability (0.0 to 1.0) for a parsed URL dictionary.
    
    Returns:
        float between 0.0 and 1.0 representing phishing likelihood.
    """
    model = load_model()
    features = extract_features(parsed)

    if model is not None:
        try:
            vector = np.array([features], dtype=np.float64)
            # Predict class 1 (phishing) probability
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(vector)[0]
                # Assuming classes are [0, 1]
                prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                prob = float(model.predict(vector)[0])
            return max(0.0, min(1.0, prob))
        except Exception as e:
            print(f"[LinkShield ML] Inference error: {e}")

    # Fallback heuristic probability if model not present
    return fallback_ml_risk(features)


def fallback_ml_risk(features: List[float]) -> float:
    """
    Deterministic baseline score used only if the .pkl model is missing.
    """
    # [url_length, domain_length, path_length, subdomain_count, is_ip, is_https,
    #  count_hyphens, count_at, count_dots, count_slashes, count_digits, ...]
    risk = 0.0
    if features[4] == 1.0:  # is_ip
        risk += 0.4
    if features[7] > 0:    # count_at
        risk += 0.3
    if features[3] >= 2:   # subdomain_count
        risk += 0.2
    if features[6] >= 2:   # hyphens
        risk += 0.15
    if features[13] == 1.0: # suspicious keyword
        risk += 0.2
    if features[14] == 1.0: # shortener
        risk += 0.15
    if features[0] > 75:   # url length
        risk += 0.1
    if features[5] == 0.0: # not https
        risk += 0.1

    return max(0.0, min(1.0, risk))


def get_ml_details(parsed: dict) -> Dict[str, Any]:
    """
    Returns rich ML telemetry for UI presentation and explainability.
    """
    prob = predict_ml_risk(parsed)
    score = int(round(prob * 100))
    features = extract_features(parsed)

    # Highlight triggered ML signals
    signals = []
    if features[4] == 1.0:
        signals.append("IP address in domain")
    if features[7] > 0:
        signals.append("@ symbol masking")
    if features[3] >= 2:
        signals.append(f"Excessive subdomains ({int(features[3])})")
    if features[6] >= 2:
        signals.append(f"Multiple hyphens in domain ({int(features[6])})")
    if features[13] == 1.0:
        signals.append("Deceptive credential keywords")
    if features[14] == 1.0:
        signals.append("Obfuscated link shortener")
    if features[10] >= 10:
        signals.append("High digit entropy")
    if features[5] == 0.0:
        signals.append("Missing HTTPS encryption")

    return {
        "probability": round(prob, 4),
        "score": score,
        "verdict": "Phishing Risk" if score >= 50 else "Legitimate",
        "confidence": round(abs(prob - 0.5) * 2, 2),  # 0 to 1 confidence
        "model_type": "Random Forest Classifier",
        "features_analyzed": len(FEATURE_NAMES),
        "signals_detected": signals,
    }
