# 🛡️ WebShield – Automated Web Security Header & CORS Scanner

> **IBM SkillsBuild Cybersecurity Bootcamp Project**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35-red?logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📋 Overview

**WebShield** is a passive, read-only web security auditing tool that allows developers
and security learners to quickly assess the security posture of any website. Enter a URL
and the tool audits HTTP security headers, CORS policies, cookie flags, HTTPS enforcement,
and information leakage — then returns a risk score, letter grade, colour-coded findings
table, and a downloadable CSV report.

This project was built as a capstone submission for the **IBM SkillsBuild Cybersecurity
Bootcamp** and demonstrates practical application of OWASP Top 10 concepts, specifically
**A05: Security Misconfiguration**.

---

## ✨ Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **URL Validation** | Accepts only http/https URLs; blocks private IP ranges (SSRF protection) |
| 2 | **Security Header Audit** | Checks 6 critical headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 3 | **CORS Misconfiguration Check** | Detects wildcard origins, reflected origins, and credentials + wildcard combinations |
| 4 | **Cookie Flag Check** | Flags missing Secure, HttpOnly, and SameSite attributes |
| 5 | **HTTPS Check** | Verifies HTTPS usage and HTTP → HTTPS redirect enforcement |
| 6 | **Redirect Transparency** | Shows entered URL, final URL after redirects, HTTP status, and HTTP→HTTPS redirect note |
| 7 | **Risk Score & Grade** | 0–100 score with A–F letter grade, progress bar, and disclaimer note |
| 8 | **Score Breakdown** | Table showing each penalised check, points deducted, and reason |
| 9 | **Results Table** | Colour-coded pandas DataFrame with per-category expandable detail |
| 10 | **Chart** | Bar chart of findings by severity |
| 11 | **CSV Export** | Download: scan metadata, score breakdown, and all findings in one CSV |

---

## 🛠️ Tech Stack

- **Python 3.10+** – core language
- **Streamlit 1.35** – web application framework
- **Requests 2.32** – HTTP client for security checks
- **Pandas 2.2** – data handling and tabular results
- **Standard library** – `socket`, `ipaddress`, `re`, `urllib.parse`

---

## 📁 Folder Structure

```
webshield/
├── app.py                        # Main Streamlit application (single file)
├── requirements.txt              # Pinned Python dependencies
├── README.md                     # This file
└── webshield-project-report.html # Standalone HTML project report
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.10 or higher
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/[YourUsername]/webshield.git
cd webshield

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Activate on Windows:
venv\Scripts\activate

# Activate on macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 How to Run

```bash
streamlit run app.py
```

The app will open automatically in your browser at **http://localhost:8501**.

---

## 📖 Usage Guide

1. **Open the app** – navigate to `http://localhost:8501`
2. **Enter a URL** – type or paste a full URL (e.g. `https://example.com`)
   - A warning is shown if you enter `http://` — HTTPS is recommended
3. **Click Run Scan** – the tool performs all passive checks in ~3–10 seconds
4. **View Results** – the page shows:
   - **Entered URL**, **Final URL** after redirects, **HTTP status code**, and a note if HTTP was redirected to HTTPS
   - Your risk grade (A–F) and score out of 100
   - A disclaimer note: *"This score measures security header and configuration hygiene only"*
   - **Score Breakdown** table — each penalised check, its severity, points deducted, and reason
   - A bar chart of findings by severity
   - A full colour-coded findings table
   - Per-category expandable detail with recommended fixes
5. **Download** – click **Download CSV** to save: scan metadata, score breakdown, and all findings

---

## 📊 Example Output

For a scan of `https://example.com`:

```
Entered URL:  https://example.com
Final URL:    https://example.com/
HTTP Status:  200

Grade: C  |  Risk Score: 37/100
ℹ️ Score measures header/config hygiene only — does not indicate active exploitation.

Score Breakdown:
  Header: Content-Security-Policy   HIGH    -15  Prevents XSS...
  Header: Strict-Transport-Security HIGH    -15  Forces HTTPS...
  Header: X-Frame-Options           MEDIUM   -7  Prevents clickjacking...
  Header: Referrer-Policy           LOW      -3  Controls referrer info...
  Header: Permissions-Policy        LOW      -3  Restricts browser APIs...
  Info Leak: Server                 LOW      -3  Exposes server software...
  Total: 46 pts → Capped score: 37/100 (Grade C)

Findings:
❌ Missing: Content-Security-Policy     [HIGH]
❌ Missing: Strict-Transport-Security   [HIGH]
✅ X-Content-Type-Options: nosniff
⚠️  X-Frame-Options: missing            [MEDIUM]
⚠️  Server header present: ECS           [LOW]
✅ CORS: No issues found
ℹ️  No cookies set
```

---

## 🔒 Security & Ethical Disclaimer

> **⚠️ IMPORTANT: Use Responsibly**
>
> This tool is intended **solely for educational purposes and authorised security testing**.
>
> - ✅ Scan only websites you **own** or have **explicit written permission** to test.
> - ❌ Do **not** use this tool against websites without authorisation.
> - ❌ This tool performs **passive, read-only** checks only — no exploitation, no brute-force.
>
> Unauthorised scanning may violate computer crime laws, including:
> - Computer Fraud and Abuse Act (CFAA) – USA
> - Computer Misuse Act 1990 – UK
> - Similar legislation in your jurisdiction
>
> The author accepts **no responsibility** for misuse of this tool.

### SSRF Protection
The tool blocks scanning of private/internal IP ranges:
- `127.0.0.0/8` (localhost)
- `10.0.0.0/8` (private)
- `172.16.0.0/12` (private)
- `192.168.0.0/16` (private)
- `169.254.0.0/16` (link-local)

---

## 🔮 Future Improvements

- [ ] **TLS/SSL Certificate Check** – expiry date, cipher strength, certificate chain
- [ ] **Subresource Integrity (SRI)** – check for SRI on external scripts/styles
- [ ] **Content-Security-Policy Parser** – deep analysis of CSP directives
- [ ] **Rate Limiting** – prevent accidental DoS by limiting scan frequency
- [ ] **PDF Report Generation** – export a polished PDF with all findings
- [ ] **CI/CD Integration** – GitHub Action to scan on every deployment

---

## 👤 Author

**[Your Name]**
- IBM SkillsBuild Cybersecurity Bootcamp
- GitHub: [https://github.com/YourUsername](https://github.com/YourUsername)
- LinkedIn: [Your LinkedIn URL]

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgements

- [OWASP Top 10](https://owasp.org/Top10/) – Security Misconfiguration (A05)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [securityheaders.com](https://securityheaders.com/) – inspiration for header checks
- IBM SkillsBuild Cybersecurity Bootcamp instructors and mentors
