from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# -------------------------
# App initialization
# -------------------------
app = FastAPI()

# -------------------------
# CORS (IMPORTANT for browser + extension)
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Load trained models
# -------------------------
email_model = joblib.load("email_model.pkl")
url_model = joblib.load("url_model.pkl")

# -------------------------
# Request schema
# -------------------------
class ScanRequest(BaseModel):
    email_text: str

# -------------------------
# URL feature extraction
# -------------------------
def extract_url_features(url: str):
    parsed = urlparse(url)
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_slashes": url.count("/"),
        "has_ip": int(parsed.netloc.replace(".", "").isdigit()),
        "has_https": int(parsed.scheme == "https"),
        "suspicious_keywords": int(
            any(k in url.lower() for k in ["login", "verify", "secure", "account", "update"])
        ),
    }

# -------------------------
# URL ML risk score (NO blacklist)
# -------------------------
def url_risk_score(url: str) -> float:
    features = extract_url_features(url)
    df = pd.DataFrame([features])
    prob = url_model.predict_proba(df)[0][1]
    return prob * 100

# -------------------------
# Main API endpoint
# -------------------------
@app.post("/scan-email")
def scan_email(req: ScanRequest):
    try:
        text = req.email_text

        # Extract URLs from email
        urls = re.findall(r"https?://\S+", text)

        # Email phishing risk
        email_risk = email_model.predict_proba([text])[0][1] * 100

        # URL phishing risk (max over all URLs)
        url_risks = [url_risk_score(u) for u in urls] if urls else [0]
        max_url_risk = max(url_risks)

        # Final decision
        final_risk = max(email_risk, max_url_risk)

        if final_risk >= 70:
            decision = "PHISHING"
        elif final_risk >= 40:
            decision = "SUSPICIOUS"
        else:
            decision = "SAFE"

        return {
            "decision": decision,
            "risk": round(final_risk, 2),
            "urls_found": urls
        }

    except Exception as e:
        # This helps debugging instead of silent 500
        return {
            "error": str(e)
        }
