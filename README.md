# CyberSentinel

## Core Idea
A **multi-layer, real-time URL risk detection system** designed to protects users from phishing attacks and online scams. 

This application is designed to both identify risky websites and educates users about online threats, by providing the phishing features that provided URL contains. 

---

## Key Features
1. **Multi-Layer Risk Detection** — Three independent scanning engines (rules, ML, external APIs) vote on every URL. Scores are fused with configurable weights and external hits trigger a priority override.
2. **Color-Coded Risk Notifications** — Every scan returns one of three verdicts:
   - 🟢 **Safe** — score below 40, no external flags
   - 🟠 **Suspicious** — score 40–69, or 2+ medium-risk pattern matches
   - 🔴 **Dangerous** — score ≥ 70, any high-risk pattern, or flagged by VirusTotal / Google Safe Browsing
3. **SHAP-Powered Explainable AI** - For phishing predictions, the top-5 SHAP feature importances are translated into human-readable sentences (e.g., "This URL contains an IP address instead of a domain name with 34.20% influence on the prediction.").
4. **Dialoger Behavioral Reasoning** — A lightweight post-scan analysis layer summarises the behavioral intent of the findings (credential theft, malware delivery, etc.).
5. **Scan Caching** — Results are persisted in SQLite and served from cache on repeated lookups, avoiding redundant external API calls.
6. **User Feedback Loop** — A `/provide-feedback` endpoint lets users correct predictions, enabling future dataset improvement.
7. **Admin Observability** — `/admin/logs` and `/admin/feedback` endpoints expose recent scan history and user corrections (API-key protected).
8. **Ethical, Privacy-First Design** — No browsing history is tracked; external APIs are called only on demand; private/loopback IPs are blocked at the perimeter.


---

## Tech Stack

| Layer                   | Technology                                              |
|-------------------------|---------------------------------------------------------|
| Language                | Python 3.13.5                                           |
| API Framework           | FastAPI + Uvicorn                                       |
| ML Model                | scikit-learn RandomForestClassifier (`.pkl` via joblib) |
| ML Explainable AI       | SHAP (TreeExplainer)                                    |
| Feature Engineering     | pandas, numpy, tldextract                               |
| External Threat Intel   | Google Safe Browsing v4, VirusTotal v3                  |

---

## Architecture (Service-Oriented Modular Layered Architecture)

```
CyberSentinel/
│
├── api.py                  # FastAPI app, endpoints, score fusion, risk classification
├── config.py               # All constants, thresholds, pattern sets
├── models.py               # Pydantic request/response schemas
├── database.py             # Async SQLite: scan cache, feedback store, admin queries
│
├── scanners/
│   ├── rule_scanner.py     # heuristic checks (HTTPS, IP, TLD, keywords, SSL, WHOIS, HTML…)
│   ├── ml_scanner.py       # RandomForest inference + SHAP explanations
│   └── external_scanner.py # Google Safe Browsing & VirusTotal async API calls
│
└── utils/
    ├── feature_extractor.py  # 50+ URL features → pandas DataFrame for the ML model
    └── logger.py             # Shared logger factory (file + console handlers)
```

---

## Scanning Pipeline

When `POST /scan-url` is called, the following steps execute:

1. **Auth & Rate Limiting** — API key validation; per-user sliding-window rate limit (default: 10 req / 60 s).
2. **Cache Check** — If the URL was scanned before, the stored result is returned immediately (`"cached": true`).
3. **Parallel Scanning** — Three engines run concurrently:
   - `RuleScanner.scan()` — 24 deterministic checks, returns `(rule_score, findings[])`.
   - `MLScanner.predict()` — RandomForest probability × 100 → `ml_score`; SHAP top-5 for phishing predictions.
   - `ExternalScanner` — Google Safe Browsing + VirusTotal called with `asyncio.gather`.
4. **Score Fusion** — `final_score = rule_score × 0.6 + ml_score × 0.4`; `+25` if any external feed flags the URL.
5. **Risk Classification** — Priority order: external flag → high-risk pattern → 2× medium pattern → score threshold.
6. **Persist & Respond** — Result saved to SQLite; full `ScanResponse` returned.

---

## Rule Scanner — Checks Performed

The `RuleScanner` performs 24 heuristic checks and accumulates scores

| Check | Score Impact             |
|---|--------------------------|
| No HTTPS | +15                      |
| IP address used instead of domain | +20                      |
| Suspicious TLD (`.tk`, `.xyz`, `.top`, etc.) | +10                      |
| Excessive subdomains (≥ 3) | +8                       |
| Long URL (> 100 chars) | +5                       |
| Homograph / IDN attack | +20                      |
| Sensitive keywords in URL | +3 per keyword (max +15) |
| Brand name impersonation | +12                      |
| Non-standard port | +8                       |
| URL shortener service | +10                      |
| Excessive query parameters (> 5) | +5                       |
| Direct executable download (`.exe`, `.apk`, etc.) | +18                      |
| Very new domain (< 30 days) | +18                      |
| Young domain (< 6 months) | +8                       |
| Expired SSL certificate | +20                      |
| SSL expiring soon (< 14 days) | +10                      |
| Unusual SSL issuer | +5                       |
| SSL validation failure | +10                      | 
| Timeout while fetching page content | +5                       |
| Multiple redirects (> 3) | +10                      |
| Hidden iframe (clickjacking indicator) | +15                      |
| Suspicious keywords in page title | +8                       |
| Obfuscated JavaScript (`eval(`, `atob(`) | +15                      |
| Password field over HTTP | +20                      |

---

## ML Feature Engineering

`feature_extractor.py` computes **50+ features** from each URL for the RandomForest model, grouped into:

- **Length features** — URL, hostname, path, query string lengths
- **Character-count features** — dots, hyphens, slashes, `@`, `%`, digits, special chars
- **Ratio features** — digit ratio, letter ratio, uppercase/lowercase ratio
- **Domain features** — domain length, TLD length, subdomain count, entropy
- **Structural flags** — `has_ip`, `has_https`, `has_port`, `double_slash_redirect`, `shortening_service`, `prefix_suffix`
- **Keyword flags** — one binary feature per suspicious keyword (`kw_login`, `kw_verify`, etc.) + total count
- **Path/Query features** — directory depth, parameter count, dangerous extension presence
- **Entropy/Randomness** — Shannon entropy of full URL and domain
- **Token features** — token count, longest token, average token length
- **Encoding flags** — `has_encoded` (percent-encoding), `has_base64`

Download the trained phishing detection model here:
[phishing_random_forest_model.pkl](https://drive.google.com/drive/folders/1j7NWBztglAbTcbvSLq6nsOfiOawpPAX8?usp=sharing)
---

## Configuration (`.env`)

```env
GOOGLE_API_KEY=your_google_safebrowsing_key
VT_API_KEY=your_virustotal_key
SECURE_API_KEY=your_api_key_here
ADMIN_API_KEY=your_api_key_here

DB_FILE=scans.db
LOG_FILE=scan_log
```

---

## Running the Server

```bash
pip install -r requirements.txt
uvicorn api:app --host 127.0.0.1 --port 8000
```

Or directly:

```bash
python api.py
```

---

## Security Notes

- Private/loopback IP URLs are blocked with HTTP 400 before any scanning begins.
- The API key is required for all mutation and admin endpoints; it is never logged.
- No user browsing history is stored — only the URL submitted for scanning and its result.