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

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "short.link", "shorte.st", "cutt.ly", "rb.gy", "tiny.cc"
}

TRUSTED_SSL_ISSUERS = ["digicert", "letsencrypt", "godaddy", "comodo", "globalsign",
                       "entrust", "sectigo", "google", "amazon", "zerossl"]

SAFE_PORTS = {80, 443, 8080, 8443}

# Numeric limits & thresholds
MAX_RULE_SCORE = 100
HTTP_TIMEOUT = 5
SSL_TIMEOUT = 10
DOMAIN_NEW_DAYS = 30
DOMAIN_YOUNG_DAYS = 180
SSL_EXPIRY_WARN_DAYS = 30
SUBDOMAIN_WARN_COUNT = 3
URL_LENGTH_WARN = 100
MAX_QUERY_PARAMS = 10
MAX_ALLOWED_REDIRECTS = 3

# HTTP settings
DEFAULT_USER_AGENT = "CyberSentinel/12.0"

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
    "Excessive subdomains",
    "Non-standard port",
    "URL shortener",
    "Many query parameters",
    "Domain less than 6 months old",
    "SSL certificate from unusual issuer",
    "Suspicious keywords in page title"
]