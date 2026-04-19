"""
Centralised configuration loaded once at startup.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# API KEYS
SECURE_API_KEY: str | None = os.getenv("SECURE_API_KEY")
ADMIN_API_KEY: str | None = os.getenv("ADMIN_API_KEY")
VT_API_KEY:     str | None = os.getenv("VT_API_KEY")
GOOGLE_API_KEY: str | None = os.getenv("GOOGLE_API_KEY")

# DATABASE
DB_FILE:       str = os.getenv("DB_FILE")
ML_MODEL_FILE: str = os.getenv("ML_MODEL_FILE")
LOG_FILE:      str = os.getenv("LOG_FILE")

# RATE LIMITING
RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))   # seconds
RATE_LIMIT_COUNT:  int = int(os.getenv("RATE_LIMIT_COUNT",  "10"))   # max requests per window

# RISK THRESHOLDS
DANGEROUS_THRESHOLD:  int = 70
SUSPICIOUS_THRESHOLD: int = 40

# SCORE WEIGHTS
RULE_WEIGHT:     float = 0.6
ML_WEIGHT:       float = 0.4
EXTERNAL_BOOST:  int   = 25   # added when an external feed flags the URL

# HTTP
DEFAULT_USER_AGENT: str = "CyberSentinel/2.0"
HTTP_TIMEOUT:       int = 8    # seconds — applied to ALL outbound requests
VT_TIMEOUT:         int = 10
SSL_TIMEOUT:        int = 3

# PATTERNS

# Security pattern sets
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online"
})

SUSPICIOUS_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "verify", "bank", "update", "password", "account", "secure",
    "payment", "billing", "confirm", "security", "urgent", "alert", "webscr",
    "validate", "admin", "activate"
})

DOWNLOAD_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".zip", ".apk", ".msi", ".bat", ".scr", ".js", ".vbs", ".dmg", ".app", ".php"
})

BRAND_NAMES: frozenset[str] = frozenset({
    "paypal", "apple", "microsoft", "google", "facebook", "amazon", "netflix",
    "bankofamerica", "wellsfargo", "chase", "dropbox", "dhl", "fedex"
})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "goo.gl", "tinyurl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do"
})

TRUSTED_SSL_ISSUERS: tuple[str, ...] = (
    "let's encrypt", "digicert", "sectigo"
)

# ML Explainability
FEATURE_DESCRIPTIONS: dict[str, str] = {

    # Length features
    "url_length": "an unusually long URL",
    "hostname_length": "a long domain hostname",
    "path_length": "a long URL path structure",
    "query_length": "an unusually long query string",

    # Character counts
    "num_dots": "many dot separators in the URL",
    "num_hyphens": "many hyphens in the URL",
    "num_underscores": "many underscores in the URL",
    "num_slashes": "many path separators in the URL",
    "num_question": "multiple question marks in the URL",
    "num_equal": "multiple parameter assignments in the URL",
    "num_at": "the '@' symbol in the URL",
    "num_ampersand": "many '&' parameter separators",
    "num_percent": "encoded characters in the URL",
    "num_digits": "a high number of numeric characters",
    "num_letters": "a high number of alphabetic characters",
    "num_special_chars": "many special characters",

    # Ratio features
    "digit_ratio": "a high ratio of numbers in the URL",
    "letter_ratio": "a high ratio of letters in the URL",

    # Domain features
    "domain_length": "a long domain name",
    "tld_length": "an unusually long top-level domain",
    "num_subdomains": "multiple subdomains",

    # Structural features
    "has_ip": "an IP address instead of a domain name",
    "prefix_suffix": "a hyphen used in the domain name",
    "domain_has_digit": "digits appearing in the domain name",
    "domain_has_hyphen": "hyphen characters in the domain name",
    "has_https": "HTTPS protocol usage",
    "has_port": "a custom network port in the URL",
    "double_slash_redirect": "a double slash pattern suggesting redirection",
    "shortening_service": "a known URL shortening service",

    # Keyword indicators
    "kw_*": "the phishing keyword '{keyword}' appearing in the URL",
    "suspicious_word_count": "multiple suspicious phishing keywords",

    # Path / Query features
    "directory_count": "many nested directories in the path",
    "parameter_count": "multiple query parameters",
    "has_extensions": "a potentially dangerous downloadable file extension",

    # Entropy / randomness
    "url_entropy": "high randomness in the URL structure",
    "domain_entropy": "a randomly generated or obfuscated domain name",

    # Case features
    "uppercase_ratio": "an unusually high ratio of uppercase letters",
    "lowercase_ratio": "a high ratio of lowercase letters",

    # Token features
    "token_count": "many segmented tokens in the URL",
    "longest_token": "an unusually long token in the URL",
    "avg_token_length": "long average token length",

    # Encoded patterns
    "has_encoded": "encoded characters within the URL",
    "has_base64": "a base64-like encoded string inside the URL"
}

SAFE_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})

# Rule-based score caps
MAX_RULE_SCORE: int = 100

# Thresholds used inside rule scanner
SUBDOMAIN_WARN_COUNT:  int = 3
URL_LENGTH_WARN:       int = 100
MAX_QUERY_PARAMS:      int = 5
MAX_ALLOWED_REDIRECTS: int = 3
DOMAIN_NEW_DAYS:       int = 30
DOMAIN_YOUNG_DAYS:     int = 180
SSL_EXPIRY_WARN_DAYS:  int = 14


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
    "Unusually long URL",
    "Too many dots",
    "Too many hyphens"
]
