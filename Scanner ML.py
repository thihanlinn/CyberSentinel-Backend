from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import requests
import sqlite3
import logging
from datetime import datetime
from urllib.parse import urlparse
import os
from dotenv import load_dotenv
from time import time
import re
import socket
import joblib
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from collections import Counter
import uvicorn

# ================== CONFIGURATION ==================

load_dotenv()

# API Keys
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
SECURE_API_KEY = os.getenv("SECURE_API_KEY")

# File Paths
DB_FILE = "scans.db"
ML_MODEL_FILE = "phishing_model.joblib"
DATASET_FOLDER = r"C:\Users\HP OMEN\OneDrive\Documents\Uni\Cyber Scanner"

# Thresholds
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_COUNT = 10
DANGEROUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40

# Security Patterns
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "bank", "update", "password", "account", "secure"}
DOWNLOAD_EXTENSIONS = {".exe", ".zip", ".msi", ".bat", ".scr", ".js", ".vbs"}

# Initialize FastAPI
app = FastAPI(title="CyberSentinel ML Scanner", version="6.0")

# Setup logging
logging.basicConfig(filename="scan_log.txt", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# ================== DATABASE ==================

def init_db():
    """Initialize database tables"""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT, user_id TEXT, risk TEXT,
                rule_score INTEGER, ml_score INTEGER, final_score INTEGER,
                findings TEXT, timestamp TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ml_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT, predicted_risk TEXT, actual_risk TEXT,
                feedback TEXT, timestamp TEXT
            )
        """)

init_db()

# ================== MODELS ==================

class URLRequest(BaseModel):
    url: str
    user_id: str = "guest"

class FeedbackRequest(BaseModel):
    url: str
    actual_risk: str
    feedback: str = ""

# ================== ML SCANNER ==================

class MLScanner:
    """Machine Learning URL classifier"""
    
    def __init__(self):
        self.model = None
        self.load_or_train()
    
    def extract_features(self, url: str) -> list:
        """Extract features from URL for ML prediction"""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        
        return [
            1 if parsed.scheme == "https" else 0,                    # has_https
            min(len(url), 200),                                      # url_length
            url.count('.'),                                          # num_dots
            url.count('-'),                                          # num_hyphens
            1 if self._is_ip(host) else 0,                           # uses_ip
            1 if any(tld in host for tld in SUSPICIOUS_TLDS) else 0, # suspicious_tld
            max(0, host.count('.') - 1),                             # num_subdomains
            1 if any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS) else 0,
            1 if any(ext in url.lower() for ext in DOWNLOAD_EXTENSIONS) else 0,
            sum(c.isdigit() for c in url) / max(len(url), 1),        # digit_ratio
        ]
    
    def _is_ip(self, host: str) -> bool:
        """Check if host is an IP address"""
        try:
            socket.inet_aton(host)
            return True
        except:
            return False
    
    def load_dataset(self):
        """Load CSV files from dataset folder"""
        if not os.path.exists(DATASET_FOLDER):
            print(f"⚠ Dataset folder not found: {DATASET_FOLDER}")
            return None, None
        
        csv_files = [f for f in os.listdir(DATASET_FOLDER) if f.lower().endswith('.csv')]
        if not csv_files:
            print("⚠ No CSV files found")
            return None, None
        
        all_features, all_labels = [], []
        
        for csv_file in csv_files:
            try:
                df = pd.read_csv(os.path.join(DATASET_FOLDER, csv_file))
                
                # Find URL and label columns
                url_col = next((col for col in df.columns if 'url' in col.lower()), None)
                label_col = next((col for col in df.columns if 'label' in col.lower() or 'class' in col.lower()), None)
                
                if not url_col or not label_col:
                    continue
                
                for _, row in df.iterrows():
                    url = str(row[url_col]).strip()
                    if url.startswith(('http://', 'https://')):
                        all_features.append(self.extract_features(url))
                        label = str(row[label_col]).lower()
                        all_labels.append(self._label_to_numeric(label))
                
            except Exception as e:
                print(f"⚠ Error reading {csv_file}: {e}")
        
        return (np.array(all_features), np.array(all_labels)) if all_features else (None, None)
    
    def _label_to_numeric(self, label: str) -> int:
        """Convert text label to numeric (0=safe, 1=suspicious, 2=dangerous)"""
        label = label.lower()
        if 'phish' in label or 'malic' in label or 'danger' in label:
            return 2
        elif 'suspic' in label or 'sus' in label:
            return 1
        elif 'legit' in label or 'benign' in label or 'safe' in label:
            return 0
        else:
            try:
                num = int(float(label))
                return 2 if num == 1 or num == -1 else 0
            except:
                return 0
    
    def create_sample_data(self):
        """Create sample data if no dataset available"""
        samples = [
            ("https://google.com", 0),
            ("https://github.com/login", 0),
            ("https://paypal.com/secure", 0),
            ("http://update-bank.tk", 1),
            ("http://192.168.1.1/login", 1),
            ("http://free-download.exe", 2),
            ("http://password-reset.xyz/bad.exe", 2),
        ]
        
        X = [self.extract_features(url) for url, _ in samples]
        y = [label for _, label in samples]
        
        return np.array(X), np.array(y)
    
    def load_or_train(self):
        """Load existing model or train new one"""
        try:
            model_data = joblib.load(ML_MODEL_FILE)
            self.model = model_data['model']
            print("✅ ML model loaded")
        except:
            print("🔄 Training new ML model...")
            
            X, y = self.load_dataset() or self.create_sample_data()
            
            self.model = DecisionTreeClassifier(max_depth=5, random_state=42)
            self.model.fit(X, y)
            
            accuracy = self.model.score(X, y)
            joblib.dump({'model': self.model, 'accuracy': accuracy}, ML_MODEL_FILE)
            
            print(f"✅ Model trained: {len(X)} samples, {accuracy:.1%} accuracy")
    
    def predict(self, url: str):
        """Predict risk level and score"""
        try:
            features = np.array([self.extract_features(url)])
            pred = self.model.predict(features)[0]
            proba = self.model.predict_proba(features)[0]
            
            # Convert to 0-100 score
            if pred == 0:    # Safe
                score = max(0, 100 * (1 - proba[0]))
            elif pred == 1:  # Suspicious
                score = 40 + (proba[1] * 30)
            else:            # Dangerous
                score = 70 + (proba[2] * 30)
            
            return min(100, score), pred
        except Exception as e:
            print(f"⚠ ML prediction error: {e}")
            return 50, 1  # Default to suspicious

# Initialize scanner
ml_scanner = MLScanner()

# ================== SECURITY SCANNER ==================

class SecurityScanner:
    """Rule-based security scanner"""
    
    @staticmethod
    def scan_url(url: str):
        """Perform rule-based security scan"""
        score, findings = 0, []
        parsed = urlparse(url)
        host = parsed.hostname or ""
        
        # Check HTTPS
        if parsed.scheme != "https":
            score += 15
            findings.append("No HTTPS")
        
        # Check IP address
        try:
            socket.inet_aton(host)
            score += 15
            findings.append("IP address as domain")
        except:
            pass
        
        # Check TLD
        if host.split(".")[-1] in SUSPICIOUS_TLDS:
            score += 10
            findings.append(f"Suspicious TLD (.{host.split('.')[-1]})")
        
        # Check URL structure
        if host.count(".") >= 3:
            score += 8
            findings.append("Many subdomains")
        
        if len(url) > 100:
            score += 5
            findings.append("Long URL")
        
        # Fetch and analyze content
        try:
            response = requests.get(url, timeout=6, allow_redirects=True,
                                  headers={'User-Agent': 'Mozilla/5.0'})
            html = response.text.lower()
            
            if len(response.history) > 3:
                score += 10
                findings.append(f"Multiple redirects ({len(response.history)})")
            
            # Check for suspicious content
            found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in html]
            if found_keywords:
                score += min(20, len(found_keywords) * 3)
                findings.append(f"Suspicious keywords: {', '.join(found_keywords[:3])}")
            
            if any(ext in html for ext in DOWNLOAD_EXTENSIONS):
                score += 12
                findings.append("Contains download link")
            
            if re.search(r"eval\(|atob\(|document\.write", html):
                score += 15
                findings.append("Obfuscated JavaScript")
            
        except requests.exceptions.Timeout:
            findings.append("Timeout")
            score += 5
        except Exception as e:
            findings.append(f"Fetch error: {str(e)[:50]}")
        
        return min(score, 100), findings

# Initialize scanner
security_scanner = SecurityScanner()

# ================== EXTERNAL SERVICES ==================

class ExternalServices:
    """External security service integrations"""
    
    @staticmethod
    def check_google_safebrowsing(url: str):
        """Check URL against Google Safe Browsing"""
        if not GOOGLE_API_KEY:
            return False, "API key not configured"
        
        try:
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
                json={
                    "client": {"clientId": "cybersentinel", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                },
                timeout=8
            )
            
            if "matches" in response.json():
                threats = [match["threatType"] for match in response.json()["matches"]]
                return True, f"Blocked by Google: {', '.join(threats)}"
            
            return False, "Not in blacklist"
            
        except Exception as e:
            return False, f"Google API error: {str(e)[:50]}"
    
    @staticmethod
    def check_virustotal(url: str):
        """Check URL against VirusTotal"""
        if not VT_API_KEY:
            return False, "API key not configured"
        
        try:
            headers = {"x-apikey": VT_API_KEY}
            
            # Submit URL
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            
            if submit.status_code == 200:
                analysis_id = submit.json()["data"]["id"]
                
                # Get report
                report = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10
                ).json()
                
                stats = report["data"]["attributes"]["stats"]
                malicious = stats.get("malicious", 0)
                
                if malicious > 0:
                    return True, f"Flagged by {malicious} vendors"
                
                return False, f"Clean ({stats.get('harmless', 0)} vendors)"
            
            return False, "Submission failed"
            
        except Exception as e:
            return False, f"VirusTotal error: {str(e)[:50]}"

# ================== RATE LIMITING ==================

user_requests = {}

def check_rate_limit(user_id: str):
    """Simple rate limiting per user"""
    now = time()
    
    # Clean old requests
    if user_id in user_requests:
        user_requests[user_id] = [t for t in user_requests[user_id] 
                                  if now - t < RATE_LIMIT_WINDOW]
    else:
        user_requests[user_id] = []
    
    # Check limit
    if len(user_requests[user_id]) >= RATE_LIMIT_COUNT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    user_requests[user_id].append(now)

# ================== ENDPOINTS ==================

@app.post("/scan-url")
def scan_url(req: URLRequest, x_api_key: str = Header(None)):
    """Main scanning endpoint"""
    # Authentication
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Rate limiting
    check_rate_limit(req.user_id)
    
    # Validate URL
    try:
        parsed = urlparse(req.url)
        if not all([parsed.scheme, parsed.netloc]):
            raise HTTPException(status_code=400, detail="Invalid URL")
    except:
        raise HTTPException(status_code=400, detail="Invalid URL")
    
    print(f"🔍 Scanning: {req.url}")
    
    # Perform scans
    rule_score, findings = security_scanner.scan_url(req.url)
    ml_score, ml_pred = ml_scanner.predict(req.url)
    
    google_hit, google_msg = ExternalServices.check_google_safebrowsing(req.url)
    vt_hit, vt_msg = ExternalServices.check_virustotal(req.url)
    
    # Combine results
    external_hit = google_hit or vt_hit
    findings.extend([google_msg, vt_msg] if "error" not in google_msg.lower() 
                    and "error" not in vt_msg.lower() else [])
    
    # Calculate final score
    final_score = int((rule_score * 0.6) + (ml_score * 0.4))
    if external_hit:
        final_score = min(100, final_score + 25)
    
    # Determine risk
    risk_levels = ["Safe", "Suspicious", "Dangerous"]
    risk = risk_levels[ml_pred] if final_score < SUSPICIOUS_THRESHOLD else \
           "Suspicious" if final_score < DANGEROUS_THRESHOLD else "Dangerous"
    
    # Add ML finding
    findings.append(f"ML Analysis: {risk_levels[ml_pred]} ({ml_score:.1f}/100)")
    
    # Log to database
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """INSERT INTO scans 
               (url, user_id, risk, rule_score, ml_score, final_score, findings, timestamp) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (req.url, req.user_id, risk, rule_score, int(ml_score),
             final_score, " | ".join(findings), datetime.utcnow().isoformat())
        )
    
    # Log activity
    logging.info(f"{req.user_id} scanned {req.url} → {risk} (Score: {final_score})")
    
    return {
        "url": req.url,
        "risk": risk,
        "scores": {"rule_based": rule_score, "ml_based": ml_score, "final": final_score},
        "ml_prediction": risk_levels[ml_pred],
        "external_checks": {
            "google_safe_browsing": not google_hit if "error" not in google_msg else "error",
            "virustotal": not vt_hit if "error" not in vt_msg else "error"
        },
        "findings": findings,
        "explanation": generate_explanation(risk, findings)
    }

@app.post("/provide-feedback")
def provide_feedback(req: FeedbackRequest, x_api_key: str = Header(None)):
    """Collect feedback for ML improvement"""
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """INSERT INTO ml_feedback 
               (url, predicted_risk, actual_risk, feedback, timestamp) 
               VALUES (?, ?, ?, ?, ?)""",
            (req.url, "unknown", req.actual_risk, req.feedback, datetime.utcnow().isoformat())
        )
    
    return {"status": "success", "message": "Feedback received"}

@app.get("/ml-model-info")
def get_ml_model_info(x_api_key: str = Header(None)):
    """Get ML model information"""
    if x_api_key != SECURE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if ml_scanner.model:
        return {
            "model_type": "Decision Tree",
            "depth": ml_scanner.model.get_depth(),
            "features_used": 10,
            "dataset_path": DATASET_FOLDER,
            "explainable": True
        }
    
    return {"status": "model_not_loaded"}

# ================== HELPER FUNCTIONS ==================

def generate_explanation(risk: str, findings: list) -> str:
    """Generate human-readable risk explanation"""
    if risk == "Dangerous":
        return f"High risk: {'; '.join(findings[:3])}"
    elif risk == "Suspicious":
        return f"Medium risk: {'; '.join(findings[:2])}"
    return "Low risk: Appears safe"

# ================== RUN APPLICATION ==================

if __name__ == "__main__":
    print("\n" + "="*50)
    print("CyberSentinel ML Scanner")
    print(f"Dataset: {DATASET_FOLDER}")
    print("="*50 + "\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
