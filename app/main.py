# app/main.py
from flask import Flask, render_template, request, jsonify
from src.predict import predict_url
import traceback
import os
import csv
from datetime import datetime

app = Flask(__name__, template_folder="templates", static_folder="static")

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "predictions.csv")

# Ensure log has header
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="", encoding="utf8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "url", "label", "model_prob", "vt_score", "safe_score", "registered_domain"])

def log_prediction(url: str, result: dict):
    registered = result.get("features", {}).get("registered_domain") or result.get("features", {}).get("domain") or ""
    vt_score = None
    if result.get("vt"):
        vt_score = result["vt"].get("vt_score")
    row = [
        datetime.utcnow().isoformat(),
        url,
        result.get("label"),
        result.get("model_prob"),
        vt_score,
        result.get("safe_score"),
        registered
    ]
    try:
        with open(LOG_FILE, "a", newline="", encoding="utf8") as f:
            w = csv.writer(f)
            w.writerow(row)
    except Exception:
        pass

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    details = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        try:
            if url == "":
                raise ValueError("Please enter a URL.")
            # Use reputation enrichment
            out = predict_url(url, phishing_threshold=0.8, include_reputation=True)
            result = out.get("label")
            details = {
                "safe_score": out.get("safe_score"),
                "model_prob": out.get("model_prob"),
                "vt": out.get("vt"),
                "features": out.get("features")
            }
            # log prediction
            log_prediction(url, out)
        except Exception as e:
            error = str(e)
            traceback.print_exc()
    return render_template("index.html", result=result, error=error, details=details)

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json() or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "No url provided"}), 400
    try:
        out = predict_url(url, phishing_threshold=0.8, include_reputation=True)
        # log
        log_prediction(url, out)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
