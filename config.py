import os
from dotenv import load_dotenv

load_dotenv()

# API KEYS
SECURE_API_KEY = os.getenv("SECURE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# DATABASE
DB_FILE = os.getenv("DB_FILE", "scans.db")

# RATE LIMITING
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_COUNT = 10

# RISK THRESHOLDS
DANGEROUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40

# PATTERNS

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online"}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "bank", "update", "password", "account", "secure",
    "payment", "billing", "confirm", "urgent", "alert"
}

DOWNLOAD_EXTENSIONS = {
    ".exe", ".zip", ".apk", ".msi", ".bat", ".scr", ".js", ".vbs", ".dmg", ".app"
}

BRAND_NAMES = [
    "paypal", "apple", "microsoft", "google", "facebook", "amazon", "netflix",
    "bankofamerica", "wellsfargo", "chase", "dropbox", "dhl", "fedex"
]


# RISK DEFINITIONS

HIGH_RISK_PATTERNS = [
    "IP address used instead of domain name",
    "Obfuscated JavaScript code",
    "Password form submitted over insecure HTTP",
    "Direct executable download"
]

MEDIUM_RISK_PATTERNS = [
    "No HTTPS encryption",
    "Suspicious TLD",
    "Sensitive keywords in URL",
    "Too many dots",
    "Too many hyphens"
]
