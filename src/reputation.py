# src/reputation.py
# VirusTotal v3 integration helper.
# Requires environment variable VIRUSTOTAL_API_KEY (or config.json fallback).
#
# This code:
# - computes a vt_score between 0.0 and 1.0 based on last_analysis_stats (malicious / harmless etc.)
# - returns a small dict with vt_score, vt_summary, vt_permalink
# - tolerant to missing API key and errors (returns None)

import os
import base64
import requests
from urllib.parse import quote_plus
import json
from time import sleep

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Optional config.json fallback in project root
if not VT_API_KEY:
    try:
        ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cfg_path = os.path.join(ROOT, "config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf8") as f:
                cfg = json.load(f)
            VT_API_KEY = cfg.get("VIRUSTOTAL_API_KEY")
    except Exception:
        VT_API_KEY = None

VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

VT_BASE = "https://www.virustotal.com/api/v3"

# Helper: compute vt_score from last_analysis_stats (0..1)
def _score_from_stats(stats: dict) -> float:
    # stats expected: {'harmless': int, 'malicious': int, 'suspicious': int, 'undetected': int, ...}
    if not isinstance(stats, dict):
        return 0.0
    total = sum(stats.get(k, 0) for k in stats)
    if total == 0:
        return 0.0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    # weigh malicious strongly, suspicious weaker
    return min(1.0, (malicious + 0.5 * suspicious) / total)

def query_virustotal_url(url: str, timeout: int = 10) -> dict | None:
    """
    Query VirusTotal for the given URL and return:
    {
      "vt_score": float(0..1),
      "vt_summary": {"malicious":int,...} or None,
      "permalink": str or None
    }
    Returns None if API key missing or call fails.
    """
    if not VT_API_KEY:
        return None

    try:
        # Per VT v3 docs, the URL id is base64url encoded (without padding) of the URL string
        # See: https://developers.virustotal.com/reference/urls
        url_bytes = url.encode()
        b64 = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
        url_get = f"{VT_BASE}/urls/{b64}"

        r = requests.get(url_get, headers=VT_HEADERS, timeout=timeout)
        if r.status_code == 404:
            # no record, attempt to submit analysis
            submit_url = f"{VT_BASE}/urls"
            r2 = requests.post(submit_url, data={"url": url}, headers=VT_HEADERS, timeout=timeout)
            if r2.status_code in (200, 201):
                # returned resource id in JSON: /analyses/{id}
                j = r2.json()
                analysis_id = j.get("data", {}).get("id")
                if analysis_id:
                    # Poll for ready result (short, with sleeps; VT may take longer)
                    analysis_url = f"{VT_BASE}/analyses/{analysis_id}"
                    for _ in range(6):  # poll up to ~30s total
                        sleep(5)
                        aresp = requests.get(analysis_url, headers=VT_HEADERS, timeout=timeout)
                        if aresp.status_code == 200:
                            ajson = aresp.json()
                            # sometimes analysis contains "stats" similar to last_analysis_stats
                            stats = None
                            try:
                                stats = ajson.get("data", {}).get("attributes", {}).get("stats")
                            except Exception:
                                stats = None
                            if stats:
                                vt_score = _score_from_stats(stats)
                                permalink = f"https://www.virustotal.com/gui/url/{b64}/detection"
                                return {"vt_score": vt_score, "vt_summary": stats, "permalink": permalink}
                    # if polling failed, fall through to return None
                    return None
            return None
        elif r.status_code == 200:
            j = r.json()
            attrs = j.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats")
            vt_score = _score_from_stats(stats)
            permalink = f"https://www.virustotal.com/gui/url/{b64}/detection"
            return {"vt_score": vt_score, "vt_summary": stats, "permalink": permalink}
        else:
            # other status codes: handle gracefully
            return None
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None
