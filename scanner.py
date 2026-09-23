"""Passive security header scanner. Implements docs/03_SECURITY_METHODOLOGY.md exactly."""
import sys
from urllib.parse import urlparse

import requests
import urllib3

FAKE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)
REQUEST_TIMEOUT = 10


class InvalidURLError(ValueError):
    pass


def validate_url(url):
    """Enforce http/https scheme and a plausible host with a TLD."""
    parsed = urlparse(url.strip())

    if parsed.scheme not in ("http", "https"):
        raise InvalidURLError("URL must start with http:// or https://")

    if not parsed.netloc:
        raise InvalidURLError("URL must include a host, e.g. https://example.com")

    hostname = parsed.hostname or ""
    if hostname != "localhost" and "." not in hostname:
        raise InvalidURLError(f"'{hostname}' does not look like a valid domain")

    return parsed.geturl()


def fetch(url):
    """GET the target with a strict timeout. Falls back to verify=False on SSL errors."""
    headers = {"User-Agent": FAKE_USER_AGENT}
    ssl_warning = False
    try:
        response = requests.get(
            url, headers=headers, timeout=REQUEST_TIMEOUT, verify=True
        )
    except requests.exceptions.SSLError:
        ssl_warning = True
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(
            url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False
        )
    return response, ssl_warning


def _get_cookie_flags(response):
    """Return [{'secure': bool, 'httponly': bool}, ...] for each Set-Cookie header."""
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookie_lines = raw_headers.getlist("Set-Cookie")
    else:
        single = response.headers.get("Set-Cookie")
        cookie_lines = [single] if single else []

    flags = []
    for line in cookie_lines:
        parts = [p.strip().lower() for p in line.split(";")]
        flags.append({"secure": "secure" in parts, "httponly": "httponly" in parts})
    return flags


def evaluate(response, ssl_warning):
    """Apply docs/03_SECURITY_METHODOLOGY.md checks and weights. Returns (score, findings)."""
    headers = response.headers
    findings = []
    score = 0

    # 2.1 Content-Security-Policy (+20)
    csp = headers.get("Content-Security-Policy", "")
    if csp.strip():
        findings.append({
            "header_name": "Content-Security-Policy", "status": "PASS", "severity": "Info",
            "description": "Content-Security-Policy header is present.",
            "recommendation": "No action needed.",
        })
        score += 20
    else:
        findings.append({
            "header_name": "Content-Security-Policy", "status": "FAIL", "severity": "High",
            "description": "Content-Security-Policy header is missing.",
            "recommendation": "Implement a strong Content-Security-Policy to restrict resource loading and mitigate Cross-Site Scripting (XSS) attacks.",
        })

    # 2.2 Strict-Transport-Security (+15)
    hsts = headers.get("Strict-Transport-Security", "")
    if "max-age" in hsts.lower():
        findings.append({
            "header_name": "Strict-Transport-Security", "status": "PASS", "severity": "Info",
            "description": "HSTS header is present with a max-age directive.",
            "recommendation": "No action needed.",
        })
        score += 15
    else:
        findings.append({
            "header_name": "Strict-Transport-Security", "status": "FAIL", "severity": "High",
            "description": "Strict-Transport-Security header is missing or improperly formatted.",
            "recommendation": "Enforce HSTS with a sufficient max-age to ensure browsers only connect via HTTPS, preventing downgrade attacks.",
        })

    # 2.3 X-Frame-Options (+15)
    xfo = headers.get("X-Frame-Options", "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        findings.append({
            "header_name": "X-Frame-Options", "status": "PASS", "severity": "Info",
            "description": f"X-Frame-Options is set to {xfo}.",
            "recommendation": "No action needed.",
        })
        score += 15
    else:
        findings.append({
            "header_name": "X-Frame-Options", "status": "FAIL", "severity": "Medium",
            "description": "X-Frame-Options header is missing or contains a weak/invalid value.",
            "recommendation": "Configure X-Frame-Options to DENY or SAMEORIGIN to protect against clickjacking attacks.",
        })

    # 2.7 Cookie Security (+15)
    cookie_flags = _get_cookie_flags(response)
    if not cookie_flags or all(c["secure"] and c["httponly"] for c in cookie_flags):
        findings.append({
            "header_name": "Cookie Security", "status": "PASS", "severity": "Info",
            "description": "All cookies (if any) are marked Secure and HttpOnly.",
            "recommendation": "No action needed.",
        })
        score += 15
    else:
        findings.append({
            "header_name": "Cookie Security", "status": "FAIL", "severity": "High",
            "description": "One or more cookies are missing the Secure or HttpOnly flag.",
            "recommendation": "Ensure all session cookies are marked with Secure, HttpOnly, and appropriately scoped SameSite attributes.",
        })

    # 2.4 X-Content-Type-Options (+10)
    xcto = headers.get("X-Content-Type-Options", "").strip().lower()
    if xcto == "nosniff":
        findings.append({
            "header_name": "X-Content-Type-Options", "status": "PASS", "severity": "Info",
            "description": "X-Content-Type-Options is set to nosniff.",
            "recommendation": "No action needed.",
        })
        score += 10
    else:
        findings.append({
            "header_name": "X-Content-Type-Options", "status": "FAIL", "severity": "Low",
            "description": "X-Content-Type-Options header is missing or incorrect.",
            "recommendation": "Set X-Content-Type-Options to 'nosniff' to prevent browsers from MIME-sniffing the response.",
        })

    # 2.5 Referrer-Policy (+10)
    if headers.get("Referrer-Policy", "").strip():
        findings.append({
            "header_name": "Referrer-Policy", "status": "PASS", "severity": "Info",
            "description": "Referrer-Policy header is present.",
            "recommendation": "No action needed.",
        })
        score += 10
    else:
        findings.append({
            "header_name": "Referrer-Policy", "status": "FAIL", "severity": "Low",
            "description": "Referrer-Policy header is missing.",
            "recommendation": "Implement a strict Referrer-Policy to prevent leakage of sensitive URL paths to third-party sites.",
        })

    # 2.6 Permissions-Policy (+10)
    if headers.get("Permissions-Policy", "").strip():
        findings.append({
            "header_name": "Permissions-Policy", "status": "PASS", "severity": "Info",
            "description": "Permissions-Policy header is present.",
            "recommendation": "No action needed.",
        })
        score += 10
    else:
        findings.append({
            "header_name": "Permissions-Policy", "status": "FAIL", "severity": "Low",
            "description": "Permissions-Policy header is missing.",
            "recommendation": "Use Permissions-Policy to explicitly disable unnecessary browser features (like camera, microphone, geolocation).",
        })

    # 2.8 Information Disclosure (+5)
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    server_generic = server == "" or ("/" not in server and any(c.isalpha() for c in server))
    if not powered_by and server_generic:
        findings.append({
            "header_name": "Information Disclosure", "status": "PASS", "severity": "Info",
            "description": "Server and X-Powered-By headers do not reveal specific software versions.",
            "recommendation": "No action needed.",
        })
        score += 5
    else:
        findings.append({
            "header_name": "Information Disclosure", "status": "FAIL", "severity": "Medium",
            "description": f"Headers reveal underlying technology versions (Server: '{server}', X-Powered-By: '{powered_by}').",
            "recommendation": "Remove or obscure the Server and X-Powered-By headers to minimize reconnaissance data available to attackers.",
        })

    if ssl_warning:
        findings.append({
            "header_name": "SSL Certificate Validation", "status": "WARNING", "severity": "Medium",
            "description": "The target's SSL certificate could not be verified (e.g. self-signed or expired). The scan proceeded without verification.",
            "recommendation": "Use a certificate from a trusted Certificate Authority and ensure the chain is complete.",
        })

    return score, findings


def classify_risk(score):
    if score >= 80:
        return "Low Risk"
    if score >= 60:
        return "Medium Risk"
    if score >= 40:
        return "High Risk"
    return "Critical Risk"


def scan(url):
    target_url = validate_url(url)
    response, ssl_warning = fetch(target_url)
    score, findings = evaluate(response, ssl_warning)
    return {
        "target_url": target_url,
        "security_score": score,
        "risk_level": classify_risk(score),
        "findings": findings,
    }


def _print_report(result):
    print(f"Target:     {result['target_url']}")
    print(f"Score:      {result['security_score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    print("-" * 60)
    for f in result["findings"]:
        print(f"[{f['status']:7}] {f['header_name']} ({f['severity']})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)

    try:
        result = scan(sys.argv[1])
    except InvalidURLError as e:
        print(f"Invalid URL: {e}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

    _print_report(result)
