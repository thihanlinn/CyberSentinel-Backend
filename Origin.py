from fastapi import FastAPI
from pydantic import BaseModel
import requests
import uvicorn

app = FastAPI()

# Your actual Google Safe Browsing API key
API_KEY = "..."

class URLRequest(BaseModel):
    url: str

@app.post("/scan-url")
def scan_url(request: URLRequest):
    scan_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    body = {
        "client": {
            "clientId": "cybersentinel-bot",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": request.url}]
        }
    }

    try:
        response = requests.post(scan_url, json=body)
        result = response.json()

        if "matches" in result:
            threat_types = list({match["threatType"] for match in result["matches"]})
            return {
                "url": request.url,
                "risk": "❌ Dangerous",
                "threatTypes": threat_types,
                "message": "This site has been flagged as a threat."
            }
        else:
            return {
                "url": request.url,
                "risk": "✅ Safe",
                "message": "No threats detected. The site appears safe."
            }

    except Exception as e:
        return {
            "risk": "⚠️ Error",
            "message": f"An error occurred during scanning: {str(e)}"
        }

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
