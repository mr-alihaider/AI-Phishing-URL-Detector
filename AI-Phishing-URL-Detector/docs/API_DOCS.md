# REST API Documentation

PhishGuard AI exposes REST endpoints for automated integration into security gateways, proxies, email filters, or SIEM pipelines.

---

## Base URL
```
http://127.0.0.1:5000
```

---

## Endpoints

### 1. Health & Status Check
- **Endpoint:** `GET /api/health`
- **Description:** Verifies service availability and returns model evaluation metrics.
- **Example Request:**
  ```bash
  curl -X GET http://127.0.0.1:5000/api/health
  ```
- **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "service": "AI-Powered Phishing URL Detection System",
    "model_loaded": true,
    "metrics": {
      "accuracy": 1.0,
      "precision": 1.0,
      "recall": 1.0,
      "f1_score": 1.0
    }
  }
  ```

---

### 2. Single URL Analysis
- **Endpoint:** `POST /api/predict`
- **Description:** Performs deep heuristic feature extraction and ML inference for a single URL.
- **Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "url": "http://paypa1-account-security-update.attacker.xyz/login.php"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "data": {
      "url": "http://paypa1-account-security-update.attacker.xyz/login.php",
      "label": "Phishing",
      "is_phishing": true,
      "risk_score": 88.1,
      "risk_level": "Critical Phishing",
      "confidence": 0.8813,
      "status_color": "danger",
      "threat_indicators": [
        "Top-Level Domain (TLD) matches high-abuse phishing registry.",
        "Insecure HTTP protocol used (missing SSL/TLS encryption).",
        "Contains credential/banking keywords: ['login', 'security', 'account']",
        "Abnormally high entropy (4.3028) - likely machine-generated."
      ],
      "features": {
        "url_length": 60,
        "hostname_length": 45,
        "path_length": 10,
        "count_dots": 3,
        "count_hyphens": 4,
        "has_ip_address": 0,
        "is_https": 0,
        "shannon_entropy": 4.3028,
        "suspicious_keyword_count": 3
      }
    }
  }
  ```

---

### 3. Batch URL Analysis
- **Endpoint:** `POST /api/batch`
- **Description:** Analyzes an array of URLs and provides aggregate threat statistics.
- **Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "urls": [
      "https://github.com",
      "http://192.168.1.1/banking/login",
      "https://wikipedia.org"
    ]
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "summary": {
      "total_scanned": 3,
      "phishing_detected": 1,
      "legitimate_verified": 2,
      "threat_percentage": 33.3
    },
    "results": [ ... ]
  }
  ```

---

### 4. Feature Telemetry
- **Endpoint:** `GET /api/features`
- **Description:** Returns the complete 22-feature ranking by Machine Learning feature importance (Gini reduction).
