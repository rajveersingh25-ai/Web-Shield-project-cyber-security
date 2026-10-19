"""
WebShield – Automated Web Security Header & CORS Scanner
=========================================================
IBM SkillsBuild Cybersecurity Bootcamp Project

A passive, read-only web security auditing tool that checks HTTP
security headers, CORS configuration, cookie flags, and HTTPS
enforcement for any user-supplied URL.

ETHICAL USE WARNING:
  Scan only websites you own or have explicit permission to test.
  This tool performs passive, read-only checks only.
"""

import io
import ipaddress
import re
import socket
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st

# ──────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebShield – Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────────────────
# CUSTOM CSS
# ──────────────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    html, body, [class*="css"] { font-family: 'Segoe UI', sans-serif; }
    .stApp { background-color: #0e1117; color: #fafafa; }

    div[data-testid="metric-container"] {
        background: #1c2333;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
    }

    .badge-high   { background:#ff4b4b; color:#fff; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
    .badge-medium { background:#ffa500; color:#000; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
    .badge-low    { background:#2ea44f; color:#fff; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
    .badge-info   { background:#58a6ff; color:#000; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }

    .grade-circle {
        width:90px; height:90px; border-radius:50%;
        display:flex; align-items:center; justify-content:center;
        font-size:36px; font-weight:700; margin:auto;
    }
    .grade-a { background:#2ea44f; color:#fff; }
    .grade-b { background:#3fb950; color:#fff; }
    .grade-c { background:#ffa500; color:#000; }
    .grade-d { background:#ff6b35; color:#fff; }
    .grade-f { background:#ff4b4b; color:#fff; }

    .section-header {
        font-size:18px; font-weight:600; color:#58a6ff;
        border-bottom:1px solid #30363d; padding-bottom:6px; margin-top:20px;
    }

    .disclaimer {
        background:#161b22; border:1px solid #f85149;
        border-radius:6px; padding:10px 14px; margin-bottom:12px;
        font-size:13px; color:#f85149;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
TIMEOUT = 10  # seconds per HTTP request

SECURITY_HEADERS: dict[str, dict] = {
    "Content-Security-Policy": {
        "severity": "High",
        "why": "Prevents XSS by restricting which resources browsers can load.",
        "fix": "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "why": "Forces HTTPS connections, preventing SSL-stripping attacks.",
        "fix": "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "why": "Prevents clickjacking by blocking the page from being iframed.",
        "fix": "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "why": "Stops browsers from MIME-sniffing a response away from the declared content-type.",
        "fix": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "why": "Controls how much referrer information is included with requests.",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "why": "Restricts which browser features (camera, microphone, etc.) the page can use.",
        "fix": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

CORS_TEST_ORIGINS: list[str] = [
    "https://evil-example.com",
    "null",
    "https://attacker.com",
]

SEVERITY_WEIGHTS: dict[str, int] = {"High": 15, "Medium": 7, "Low": 3}

# Private / internal IP ranges blocked (SSRF protection)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# ──────────────────────────────────────────────────────────────────────────────
# INPUT VALIDATION & SSRF PROTECTION
# ──────────────────────────────────────────────────────────────────────────────

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate that the URL is http/https and does not resolve to a
    private/internal IP address (SSRF protection).

    Returns (is_valid, message).
    """
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return False, "❌ URL must start with http:// or https://"

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False, "❌ Could not parse hostname from URL."

    if hostname.lower() in ("localhost", "::1"):
        return False, "❌ Scanning localhost/internal hosts is not allowed."

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, f"❌ Could not resolve hostname: {hostname}"

    for ai in addr_infos:
        ip = ipaddress.ip_address(ai[4][0])
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False, f"❌ Scanning private/internal IP ranges is not allowed ({ip})."

    return True, "OK"


# ──────────────────────────────────────────────────────────────────────────────
# HTTP FETCH HELPER
# ──────────────────────────────────────────────────────────────────────────────

def fetch_url(
    url: str,
    method: str = "GET",
    extra_headers: Optional[dict] = None,
    allow_redirects: bool = True,
) -> Optional[requests.Response]:
    """
    Perform a safe HTTP request. Returns None on any error.
    Uses a browser-like User-Agent for realistic server responses.
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        )
    }
    if extra_headers:
        headers.update(extra_headers)
    try:
        return requests.request(
            method,
            url,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=allow_redirects,
            verify=True,
        )
    except (
        requests.exceptions.SSLError,
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.RequestException,
    ):
        return None


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY CHECKS
# ──────────────────────────────────────────────────────────────────────────────

def check_security_headers(response: requests.Response) -> list[dict]:
    """Check for the presence of six critical HTTP security headers."""
    findings: list[dict] = []
    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    for header, meta in SECURITY_HEADERS.items():
        present = header.lower() in resp_headers
        value = resp_headers.get(header.lower(), "—")
        findings.append({
            "Check": f"Header: {header}",
            "Status": "✅ Present" if present else "❌ Missing",
            "Severity": "Info" if present else meta["severity"],
            "Value": value if present else "Not set",
            "Why It Matters": meta["why"],
            "Recommended Fix": meta["fix"] if not present else "—",
            "Category": "Security Headers",
        })
    return findings


def check_cors(url: str) -> list[dict]:
    """
    Send requests with crafted Origin headers and flag wildcard or
    reflected Access-Control-Allow-Origin responses.
    """
    findings: list[dict] = []
    for origin in CORS_TEST_ORIGINS:
        resp = fetch_url(url, extra_headers={"Origin": origin})
        if resp is None:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            if acac == "true":
                severity, status = "High", "🔴 Wildcard + Credentials"
                note = (
                    "CRITICAL: Wildcard ACAO with Allow-Credentials: true. "
                    "Browsers block this combination, but it signals a misconfiguration."
                )
            else:
                severity, status = "Medium", "⚠️ Wildcard ACAO"
                note = "Server returns '*' — any origin can read responses."
        elif acao and acao.strip() == origin:
            severity, status = "High", "🔴 Origin Reflected"
            note = (
                f"Server blindly reflects the supplied Origin ({origin}). "
                "Attackers can craft requests from any domain."
            )
        else:
            continue

        findings.append({
            "Check": f"CORS: Origin={origin}",
            "Status": status,
            "Severity": severity,
            "Value": f"ACAO: {acao} | ACAC: {acac or 'not set'}",
            "Why It Matters": note,
            "Recommended Fix": "Restrict ACAO to an explicit allowlist. Never combine wildcard with credentials.",
            "Category": "CORS",
        })

    if not findings:
        findings.append({
            "Check": "CORS Policy",
            "Status": "✅ No Issues Found",
            "Severity": "Info",
            "Value": "No wildcard or reflected origin detected",
            "Why It Matters": "CORS appears properly restricted.",
            "Recommended Fix": "—",
            "Category": "CORS",
        })
    return findings


def check_cookies(response: requests.Response) -> list[dict]:
    """Flag cookies that are missing Secure, HttpOnly, or SameSite flags."""
    findings: list[dict] = []
    set_cookies: list[str] = response.raw.headers.getlist("Set-Cookie")

    if not set_cookies:
        findings.append({
            "Check": "Cookies",
            "Status": "ℹ️ No Cookies Set",
            "Severity": "Info",
            "Value": "—",
            "Why It Matters": "No cookies were set in this response.",
            "Recommended Fix": "—",
            "Category": "Cookies",
        })
        return findings

    for cookie_str in set_cookies:
        cl = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()
        missing = []
        if "secure"   not in cl: missing.append("Secure")
        if "httponly" not in cl: missing.append("HttpOnly")
        if "samesite" not in cl: missing.append("SameSite")

        if missing:
            severity = "High" if ("Secure" in missing or "HttpOnly" in missing) else "Medium"
            findings.append({
                "Check": f"Cookie: {name}",
                "Status": f"⚠️ Missing: {', '.join(missing)}",
                "Severity": severity,
                "Value": cookie_str[:120],
                "Why It Matters": (
                    "Missing Secure exposes the cookie over HTTP; "
                    "missing HttpOnly allows JS access; "
                    "missing SameSite enables CSRF."
                ),
                "Recommended Fix": f"Set-Cookie: {name}=<value>; Secure; HttpOnly; SameSite=Strict",
                "Category": "Cookies",
            })
        else:
            findings.append({
                "Check": f"Cookie: {name}",
                "Status": "✅ Flags OK",
                "Severity": "Info",
                "Value": cookie_str[:120],
                "Why It Matters": "All recommended cookie flags are present.",
                "Recommended Fix": "—",
                "Category": "Cookies",
            })
    return findings


def check_https(url: str, response: requests.Response) -> list[dict]:
    """
    Check HTTPS usage, HTTP→HTTPS redirect enforcement, and
    server information leakage via Server / X-Powered-By headers.
    """
    findings: list[dict] = []
    parsed = urlparse(url)

    # 1. Scheme check
    if parsed.scheme == "https":
        findings.append({
            "Check": "HTTPS Enabled",
            "Status": "✅ Using HTTPS",
            "Severity": "Info",
            "Value": "HTTPS",
            "Why It Matters": "Traffic is encrypted in transit.",
            "Recommended Fix": "—",
            "Category": "HTTPS",
        })
    else:
        findings.append({
            "Check": "HTTPS Enabled",
            "Status": "❌ Using HTTP",
            "Severity": "High",
            "Value": "HTTP",
            "Why It Matters": "Traffic is transmitted in plaintext.",
            "Recommended Fix": "Enforce HTTPS and redirect all HTTP traffic.",
            "Category": "HTTPS",
        })

    # 2. HTTP → HTTPS redirect
    if parsed.scheme == "https":
        http_url = url.replace("https://", "http://", 1)
        hr = fetch_url(http_url, allow_redirects=False)
        if hr and hr.status_code in (301, 302, 307, 308):
            loc = hr.headers.get("Location", "")
            if loc.startswith("https://"):
                findings.append({
                    "Check": "HTTP→HTTPS Redirect",
                    "Status": "✅ Redirects to HTTPS",
                    "Severity": "Info",
                    "Value": f"{hr.status_code} → {loc}",
                    "Why It Matters": "HTTP visitors are safely upgraded to HTTPS.",
                    "Recommended Fix": "—",
                    "Category": "HTTPS",
                })
            else:
                findings.append({
                    "Check": "HTTP→HTTPS Redirect",
                    "Status": "⚠️ Redirects but not to HTTPS",
                    "Severity": "Medium",
                    "Value": f"{hr.status_code} → {loc}",
                    "Why It Matters": "HTTP traffic is not being upgraded to HTTPS.",
                    "Recommended Fix": "Ensure HTTP redirects point to https://",
                    "Category": "HTTPS",
                })
        elif hr:
            findings.append({
                "Check": "HTTP→HTTPS Redirect",
                "Status": "⚠️ No Redirect",
                "Severity": "Medium",
                "Value": f"HTTP {hr.status_code}",
                "Why It Matters": "HTTP is served without redirecting to HTTPS.",
                "Recommended Fix": "Add a 301 redirect from HTTP to HTTPS.",
                "Category": "HTTPS",
            })

    # 3. Information leakage
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        val = response.headers.get(h)
        if val:
            findings.append({
                "Check": f"Info Leak: {h}",
                "Status": "⚠️ Header Present",
                "Severity": "Low",
                "Value": val,
                "Why It Matters": "Exposes server software/version, aiding targeted exploits.",
                "Recommended Fix": f"Remove or obscure the '{h}' response header.",
                "Category": "Information Leakage",
            })
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# RISK SCORING
# ──────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(findings: list[dict]) -> tuple[int, str, list[dict]]:
    """
    Sum severity penalty weights → 0–100 score → A–F grade.
    Weights: High=15, Medium=7, Low=3. Info findings carry no penalty.
    Grade bands: A≤10, B≤25, C≤45, D≤65, F>65.

    Returns (score, grade, breakdown) where breakdown is a list of dicts
    with keys: Check, Points Deducted, Reason — one row per penalised finding.
    """
    breakdown: list[dict] = []
    total = 0
    for f in findings:
        pts = SEVERITY_WEIGHTS.get(f.get("Severity", "Info"), 0)
        if pts > 0:
            total += pts
            breakdown.append({
                "Check": f["Check"],
                "Points Deducted": pts,
                "Severity": f["Severity"],
                "Reason": f["Why It Matters"],
            })
    score = min(100, total)
    if score <= 10:   grade = "A"
    elif score <= 25: grade = "B"
    elif score <= 45: grade = "C"
    elif score <= 65: grade = "D"
    else:             grade = "F"
    return score, grade, breakdown


# ──────────────────────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────

def run_scan(url: str) -> dict:
    """
    Run all security checks against the target URL.
    Returns a result dict with keys:
      url, final_url, redirected_to_https, scanned_at, status_code,
      findings, risk_score, grade, score_breakdown, error.
    """
    response = fetch_url(url)
    if response is None:
        return {
            "url": url,
            "final_url": url,
            "redirected_to_https": False,
            "scanned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "status_code": None,
            "findings": [],
            "risk_score": 0,
            "grade": "?",
            "score_breakdown": [],
            "error": f"Could not connect to {url}. Check the URL and try again.",
        }

    # Capture the final URL after any redirects
    final_url: str = response.url
    redirected_to_https: bool = (
        urlparse(url).scheme == "http" and urlparse(final_url).scheme == "https"
    )

    findings: list[dict] = []
    findings.extend(check_security_headers(response))
    findings.extend(check_cors(url))
    findings.extend(check_cookies(response))
    findings.extend(check_https(url, response))

    score, grade, breakdown = calculate_risk_score(findings)
    return {
        "url": url,
        "final_url": final_url,
        "redirected_to_https": redirected_to_https,
        "scanned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status_code": response.status_code,
        "findings": findings,
        "risk_score": score,
        "grade": grade,
        "score_breakdown": breakdown,
        "error": None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ──────────────────────────────────────────────────────────────────────────────
if "last_result" not in st.session_state:
    st.session_state.last_result = None


# ──────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ──────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ WebShield")
    st.markdown("**Automated Web Security Scanner**")
    st.divider()

    st.markdown(
        """
        <div class="disclaimer">
        ⚠️ <strong>Ethical Use Warning</strong><br>
        Scan only websites you <u>own</u> or have
        <u>explicit permission</u> to test.
        Unauthorised scanning may violate laws and terms of service.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### 📖 How to Use")
    st.markdown(
        """
        1. Enter a target URL (http or https)
        2. Click **Run Scan**
        3. Review the risk grade, findings table, and chart
        4. Download the results as CSV
        """
    )

    st.markdown("### 🔍 What Is Checked")
    for item in [
        "🔒 6 Security Headers",
        "🌐 CORS Misconfiguration",
        "🍪 Cookie Flags",
        "🔐 HTTPS Enforcement",
        "📡 Information Leakage",
    ]:
        st.markdown(f"- {item}")

    st.divider()
    st.caption("🎓 IBM SkillsBuild Cybersecurity Bootcamp")
    st.caption("Passive, read-only checks only.")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN CONTENT
# ──────────────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ WebShield – Web Security Scanner")
st.markdown(
    "Enter a URL to perform a **passive security audit**. "
    "The scan checks HTTP headers, CORS policy, cookie flags, and HTTPS enforcement."
)
st.markdown(
    """
    <div class="disclaimer">
    ⚠️ <strong>Disclaimer:</strong> Use this tool only on websites you own or have
    written permission to test. This tool performs passive, read-only checks only
    and does not exploit any vulnerabilities.
    </div>
    """,
    unsafe_allow_html=True,
)

# ── URL input & scan button ──────────────────────────────────────────────────
url_input = st.text_input(
    "🌐 Target URL",
    value="https://example.com",
    placeholder="https://example.com",
    help="Full URL including http:// or https://",
)

col_scan, col_clear = st.columns([1, 8])
with col_scan:
    scan_clicked = st.button("🚀 Run Scan", type="primary", use_container_width=True)
with col_clear:
    if st.button("🗑️ Clear", use_container_width=False):
        st.session_state.last_result = None
        st.rerun()

# ── HTTP warning ─────────────────────────────────────────────────────────────
if url_input.strip().lower().startswith("http://"):
    st.warning(
        "⚠️ You entered an HTTP URL. HTTPS is strongly recommended — "
        "HTTP transmits data in plaintext and is missing transport-layer security."
    )

# ── Run scan ─────────────────────────────────────────────────────────────────
if scan_clicked:
    if not url_input.strip():
        st.error("Please enter a URL.")
    else:
        valid, msg = validate_url(url_input.strip())
        if not valid:
            st.error(msg)
        else:
            with st.spinner(f"🔍 Scanning {url_input.strip()} …"):
                result = run_scan(url_input.strip())
            if result["error"]:
                st.error(result["error"])
            else:
                st.session_state.last_result = result
                st.success(
                    f"✅ Scan complete — {len(result['findings'])} checks performed."
                )

# ── Results ──────────────────────────────────────────────────────────────────
result = st.session_state.last_result
if result is not None and result.get("error") is None:
    st.divider()

    # ── URL / redirect info ──────────────────────────────────────────
    entered_url = result["url"]
    final_url   = result.get("final_url", entered_url)
    redirected  = result.get("redirected_to_https", False)

    st.markdown(f"### Results for `{entered_url}`")

    url_info_parts = [
        f"**Entered URL:** `{entered_url}`",
        f"**Final URL:** `{final_url}`",
        f"**HTTP Status:** {result['status_code']}",
    ]
    if final_url != entered_url:
        url_info_parts.append(f"**Redirected:** `{entered_url}` → `{final_url}`")
    if redirected:
        url_info_parts.append("✅ **HTTP → HTTPS redirect detected** — the server upgrades plain HTTP connections to HTTPS.")

    for part in url_info_parts:
        st.markdown(part)
    st.caption(f"Scanned: {result['scanned_at']}")

    # ── Grade & metrics ──────────────────────────────────────────────
    st.markdown('<div class="section-header">🎯 Risk Assessment</div>', unsafe_allow_html=True)

    findings = result["findings"]
    high_n = sum(1 for f in findings if f["Severity"] == "High")
    med_n  = sum(1 for f in findings if f["Severity"] == "Medium")
    low_n  = sum(1 for f in findings if f["Severity"] == "Low")
    grade  = result["grade"]

    col_g, col_s, col_h, col_m, col_l = st.columns(5)
    with col_g:
        st.markdown(
            f'<div class="grade-circle grade-{grade.lower()}">{grade}</div>'
            "<div style='text-align:center;font-size:12px;color:#8b949e;margin-top:4px;'>Grade</div>",
            unsafe_allow_html=True,
        )
    with col_s: st.metric("Risk Score", f"{result['risk_score']}/100")
    with col_h: st.metric("🔴 High",   high_n)
    with col_m: st.metric("🟡 Medium", med_n)
    with col_l: st.metric("🟢 Low",    low_n)

    st.progress(result["risk_score"] / 100)

    # Score disclaimer note
    st.caption(
        "ℹ️ This score measures security header and configuration hygiene only. "
        "It does not mean the site has been hacked or is vulnerable to attacks."
    )

    # ── Score Breakdown ──────────────────────────────────────────────
    st.markdown('<div class="section-header">🔢 Score Breakdown</div>', unsafe_allow_html=True)
    breakdown = result.get("score_breakdown", [])
    if breakdown:
        bd_df = pd.DataFrame(breakdown)[["Check", "Severity", "Points Deducted", "Reason"]]

        def _colour_bd_sev(val: str) -> str:
            return {
                "High":   "background-color:#3d1f1f;color:#ff4b4b;",
                "Medium": "background-color:#3d2e00;color:#ffa500;",
                "Low":    "background-color:#1a2e1a;color:#2ea44f;",
            }.get(val, "")

        st.dataframe(
            bd_df.style.applymap(_colour_bd_sev, subset=["Severity"]),
            use_container_width=True,
            hide_index=True,
        )
        st.caption(
            f"Total before cap: {sum(r['Points Deducted'] for r in breakdown)} pts  "
            f"→  Capped score: {result['risk_score']}/100"
        )
    else:
        st.success("🎉 No penalties — all checks passed!")

    # ── Chart: findings by severity ──────────────────────────────────
    st.markdown('<div class="section-header">📊 Findings by Severity</div>', unsafe_allow_html=True)
    sev_counts = (
        pd.Series([f["Severity"] for f in findings if f["Severity"] != "Info"])
        .value_counts()
        .reindex(["High", "Medium", "Low"])
        .dropna()
        .astype(int)
        .reset_index()
    )
    sev_counts.columns = ["Severity", "Count"]
    if not sev_counts.empty:
        st.bar_chart(sev_counts.set_index("Severity"))
    else:
        st.success("🎉 No issues found — nothing to chart.")

    # ── Findings table ───────────────────────────────────────────────
    st.markdown('<div class="section-header">📋 Detailed Findings</div>', unsafe_allow_html=True)

    df = pd.DataFrame(findings)

    def _colour_sev(val: str) -> str:
        return {
            "High":   "background-color:#3d1f1f;color:#ff4b4b;",
            "Medium": "background-color:#3d2e00;color:#ffa500;",
            "Low":    "background-color:#1a2e1a;color:#2ea44f;",
            "Info":   "background-color:#1a2233;color:#58a6ff;",
        }.get(val, "")

    st.dataframe(
        df.style.applymap(_colour_sev, subset=["Severity"]),
        use_container_width=True,
        height=420,
    )

    # ── Per-category expanders ───────────────────────────────────────
    st.markdown('<div class="section-header">🔎 Findings by Category</div>', unsafe_allow_html=True)
    for cat in df["Category"].unique():
        cat_df = df[df["Category"] == cat]
        n_issues = len(cat_df[cat_df["Severity"] != "Info"])
        label = f"{'⚠️' if n_issues else '✅'} {cat} ({n_issues} issue{'s' if n_issues != 1 else ''})"
        with st.expander(label, expanded=(n_issues > 0)):
            for _, row in cat_df.iterrows():
                sev = row["Severity"].lower()
                st.markdown(
                    f"**{row['Check']}** — "
                    f'<span class="badge-{sev}">{row["Severity"]}</span> {row["Status"]}',
                    unsafe_allow_html=True,
                )
                if row["Value"] != "—":
                    st.code(row["Value"], language=None)
                st.markdown(f"📌 **Why it matters:** {row['Why It Matters']}")
                if row["Recommended Fix"] != "—":
                    st.markdown(f"🔧 **Fix:** `{row['Recommended Fix']}`")
                st.divider()

    # ── CSV download ─────────────────────────────────────────────────
    st.markdown('<div class="section-header">⬇️ Export</div>', unsafe_allow_html=True)
    hostname = urlparse(result["url"]).hostname or "unknown"
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Build enriched CSV: meta block + score breakdown + findings
    buf = io.StringIO()
    # Section 1: scan metadata
    meta_df = pd.DataFrame([{
        "Field": "Entered URL",      "Value": result["url"],
    }, {
        "Field": "Final URL",        "Value": result.get("final_url", result["url"]),
    }, {
        "Field": "HTTP Status",      "Value": result["status_code"],
    }, {
        "Field": "Redirected to HTTPS", "Value": str(result.get("redirected_to_https", False)),
    }, {
        "Field": "Scanned At",       "Value": result["scanned_at"],
    }, {
        "Field": "Risk Score",       "Value": f"{result['risk_score']}/100",
    }, {
        "Field": "Grade",            "Value": result["grade"],
    }])
    buf.write("# SCAN METADATA\n")
    meta_df.to_csv(buf, index=False)

    # Section 2: score breakdown
    buf.write("\n# SCORE BREAKDOWN\n")
    if breakdown:
        pd.DataFrame(breakdown)[["Check", "Severity", "Points Deducted", "Reason"]].to_csv(buf, index=False)
    else:
        buf.write("No penalties — all checks passed.\n")

    # Section 3: detailed findings
    buf.write("\n# DETAILED FINDINGS\n")
    df.to_csv(buf, index=False)

    st.download_button(
        "📥 Download CSV",
        data=buf.getvalue().encode("utf-8"),
        file_name=f"webshield_{hostname}_{ts}.csv",
        mime="text/csv",
    )
