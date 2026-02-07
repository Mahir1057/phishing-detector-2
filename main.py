from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()

# ---- Load your trained models here ----
# email_model
# url_model
# PHISHTANK_SET

class ScanRequest(BaseModel):
    email_text: str

@app.post("/scan-email")
def scan_email(req: ScanRequest):
    text = req.email_text

    urls = re.findall(r'https?://\S+', text)

    email_risk = email_model.predict_proba([text])[0][1] * 100
    max_url_risk = 0

    for url in urls:
        if url in PHISHTANK_SET:
            max_url_risk = 100
            break
        else:
            # your URL ML risk function
            risk = url_risk_score(url)
            max_url_risk = max(max_url_risk, risk)

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
