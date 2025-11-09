# src/predict.py
# Loads trained model, performs feature extraction, optional VirusTotal reputation check,
# and computes a single "safe_score" (0-100) combining model probability and vt_score.

import os
import joblib
import pandas as pd
from src.feature_extraction import extract_features
from src.reputation import query_virustotal_url
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, "phishguard_model.pkl")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Train the model first.")

model = joblib.load(MODEL_PATH)

# whitelist loader (optional)
WHITELIST_PATH = os.path.join(ROOT, "data", "whitelist.txt")
_whitelist = set()
if os.path.exists(WHITELIST_PATH):
    try:
        with open(WHITELIST_PATH, "r", encoding="utf8") as f:
            _whitelist = set(line.strip().lower() for line in f if line.strip())
    except Exception:
        _whitelist = set()

def is_whitelisted(registered_domain: str) -> bool:
    if not registered_domain:
        return False
    return registered_domain.lower() in _whitelist

def _compute_safe_score(model_prob: float | None, vt_score: float | None, weights=(0.65, 0.35)) -> float:
    """
    Combine model_prob and vt_score into a single 0..100 safe score.
    model_prob: probability of phishing (0..1) from ML model (higher => more suspicious)
    vt_score: vt-derived suspiciousness (0..1, higher => more suspicious)
    We convert suspiciousness -> safety: safety = 1 - suspiciousness.
    final safe_score = 100 * (w1 * safety_from_model + w2 * safety_from_vt)
    """
    w_model, w_vt = weights
    # Convert model_prob (suspiciousness) -> safety
    if model_prob is None:
        safety_model = 0.5
    else:
        safety_model = 1.0 - float(model_prob)
    if vt_score is None:
        safety_vt = 0.5
    else:
        safety_vt = 1.0 - float(vt_score)
    # normalize weights if vt_score missing
    if vt_score is None:
        w_model = 1.0
        w_vt = 0.0
    score = (w_model * safety_model + w_vt * safety_vt) / (w_model + w_vt)
    return round(float(score) * 100.0, 2)

def predict_url(url: str, phishing_threshold: float = 0.8, include_reputation: bool = True) -> dict:
    """
    Returns a dict:
    {
      "label": "Phishing"|"Legitimate",
      "model_prob": float or None,
      "vt": {vt_score,float, vt_summary, permalink} or None,
      "safe_score": float  # 0..100 where higher is safer
      "features": { ... }
    }
    """
    feats = extract_features(url, include_network=False)
    registered = feats.get("registered_domain") or feats.get("domain") or ""
    # whitelist override
    if is_whitelisted(registered):
        return {
            "label": "Legitimate",
            "model_prob": 0.0,
            "vt": None,
            "safe_score": 100.0,
            "features": feats
        }

    # Build dataframe aligned to model
    df = pd.DataFrame([feats])
    # drop textual columns if present
    for c in ["domain", "registered_domain", "subdomain"]:
        if c in df.columns:
            df = df.drop(columns=[c])
    df = df.fillna(0)

    # align expected columns if model stores feature names
    try:
        expected = list(model.feature_names_in_)
        df = df.reindex(columns=expected, fill_value=0)
    except Exception:
        pass

    # model probability (1 => phishing)
    model_prob = None
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(df)[0]
            # find index for phishing class (1)
            # many sklearn models use classes_ attribute
            if hasattr(model, "classes_"):
                classes = list(model.classes_)
                # if classes_ are [0,1], find index of 1
                if 1 in classes:
                    idx = classes.index(1)
                    model_prob = float(probs[idx])
                else:
                    # fallback: assume second column is phishing
                    model_prob = float(probs[-1])
            else:
                model_prob = float(probs[-1])
        else:
            pred = model.predict(df)[0]
            model_prob = 1.0 if int(pred) == 1 else 0.0
    except Exception:
        model_prob = None

    # VirusTotal reputation enrichment (optional)
    vt = None
    vt_score = None
    if include_reputation:
        try:
            vt = query_virustotal_url(url)
            if vt and isinstance(vt, dict):
                vt_score = vt.get("vt_score")
        except Exception:
            vt = None
            vt_score = None

    safe_score = _compute_safe_score(model_prob, vt_score)

    # decide label using threshold and vt (vt influences safe_score but not forced)
    label = "Phishing" if (model_prob is not None and model_prob >= phishing_threshold) else "Legitimate"

    # if vt strongly malicious (vt_score close to 1) and model low, we can still mark phishing
    if vt_score is not None and vt_score >= 0.9 and (model_prob is None or model_prob < phishing_threshold):
        label = "Phishing"

    return {
        "label": label,
        "model_prob": round(model_prob, 4) if model_prob is not None else None,
        "vt": vt,
        "safe_score": safe_score,
        "features": feats
    }
