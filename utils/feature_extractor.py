"""
URL feature engineering for the ML model.
"""

import math
import re
from urllib.parse import urlparse, parse_qs

import numpy as np
import pandas as pd
import tldextract

from config import (SUSPICIOUS_KEYWORDS, URL_SHORTENERS, DOWNLOAD_EXTENSIONS)

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    prob = [text.count(c) / length for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


# Compute the 50+ URL features expected by the phishing RandomForest model.
def extract_features(url: str) -> pd.DataFrame:
    parsed = urlparse(url)
    ext    = tldextract.extract(url)

    hostname: str = parsed.netloc or ""
    path:     str = parsed.path or ""
    query:    str = parsed.query or ""
    url_len:  int = len(url) or 1  # avoid division by zero

    digits  = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)

    tokens = re.split(r"[./?=&\-]", url)
    token_lengths = [len(t) for t in tokens if t]

    features: dict = {
        # Length features
        "url_length":       len(url),
        "hostname_length":  len(hostname),
        "path_length":      len(path),
        "query_length":     len(query),
        # Character-count features
        "num_dots":         url.count("."),
        "num_hyphens":      url.count("-"),
        "num_underscores":  url.count("_"),
        "num_slashes":      url.count("/"),
        "num_question":     url.count("?"),
        "num_equal":        url.count("="),
        "num_at":           url.count("@"),
        "num_ampersand":    url.count("&"),
        "num_percent":      url.count("%"),
        "num_digits":       digits,
        "num_letters":      letters,
        "num_special_chars":len(re.findall(r"[^\w]", url)),
        # Ratio features
        "digit_ratio":      digits  / url_len,
        "letter_ratio":     letters / url_len,
        # Domain features
        "domain_length":    len(ext.domain),
        "tld_length":       len(ext.suffix),
        "num_subdomains":   len(ext.subdomain.split(".")) if ext.subdomain else 0,
        # Structural features
        "has_ip":           1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "prefix_suffix":    1 if "-" in ext.domain else 0,
        "domain_has_digit": 1 if any(c.isdigit() for c in ext.domain) else 0,
        "domain_has_hyphen":1 if "-" in ext.domain else 0,
        "has_https":        1 if parsed.scheme == "https" else 0,
        "has_port":         1 if ":" in hostname else 0,
        "double_slash_redirect":    1 if "//" in url[8:] else 0,
        "shortening_service":       1 if any(s in hostname for s in URL_SHORTENERS) else 0,
        **{f"kw_{word}":    1 if word in url.lower() else 0 for word in SUSPICIOUS_KEYWORDS},
        "suspicious_word_count": sum(word in url.lower() for word in SUSPICIOUS_KEYWORDS),
        # Path / Query Features
        "directory_count":  path.count("/"),
        "parameter_count":  len(parse_qs(query)),
        "has_extensions":   1 if any(extension in path for extension in DOWNLOAD_EXTENSIONS) else 0,
        # Entropy
        "url_entropy":      _entropy(url),
        "domain_entropy":   _entropy(ext.domain),
        # Case features
        "uppercase_ratio":  sum(c.isupper() for c in url) / len(url) if len(url) > 0 else 0,
        "lowercase_ratio":  sum(c.islower() for c in url) / len(url) if len(url) > 0 else 0,
        # Token Features
        "token_count":      len(token_lengths),
        "longest_token":    max(token_lengths) if token_lengths else 0,
        "avg_token_length": float(np.mean(token_lengths)) if token_lengths else 0.0,
        # Encoded / Suspicious Patterns
        "has_encoded":      1 if "%20" in url or "%3A" in url else 0,
        "has_base64":       1 if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url) else 0,
    }

    return pd.DataFrame([features])
