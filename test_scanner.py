"""Offline checks for scanner logic. Usage: python test_scanner.py"""
from types import SimpleNamespace

import scanner


def fake(url="https://a.com/", status=200, headers=None, text="<html>ok</html>", history=()):
    pairs = headers.items() if isinstance(headers, dict) else (headers or [])
    return SimpleNamespace(
        url=url, status_code=status, text=text, history=list(history),
        headers=scanner.make_headers(pairs),
    )


def status_of(check, **kwargs):
    return check(fake(**kwargs))[0]


def main():
    # Bot wall detection
    assert scanner.detect_bot_challenge(fake()) is None
    assert scanner.detect_bot_challenge(fake(status=403))
    assert scanner.detect_bot_challenge(fake(text="<meta content='/?bm-verify=x'>"))
    assert scanner.detect_bot_challenge(fake(status=202, headers={"X-Amzn-Waf-Action": "challenge"}))

    # CSP: must actually restrict scripts
    csp = lambda v: status_of(scanner._check_csp, headers={"Content-Security-Policy": v})
    assert status_of(scanner._check_csp) == "FAIL"
    assert status_of(scanner._check_csp, headers={"Content-Security-Policy-Report-Only": "default-src 'self'"}) == "FAIL"
    assert csp("upgrade-insecure-requests;report-uri https://m.example/") == "FAIL"  # amazon.in
    assert csp("default-src 'self'") == "PASS"
    assert csp("default-src 'none'; script-src cdn.example.com") == "PASS"
    assert csp("script-src 'self' 'unsafe-inline'") == "WARNING"
    assert csp("script-src 'nonce-abc' 'unsafe-inline' https: 'strict-dynamic'") == "PASS"
    assert csp("default-src *") == "WARNING"
    two = [("Content-Security-Policy", "script-src 'self' 'unsafe-inline'"), ("Content-Security-Policy", "script-src 'nonce-x' 'strict-dynamic'")]
    assert status_of(scanner._check_csp, headers=two) == "PASS"  # strictest policy decides
    http_rows = [f["header_name"] for f in scanner.evaluate(fake(url="http://a.com/"), False)[1]]
    assert "HTTPS" in http_rows and "HTTPS" not in [f["header_name"] for f in scanner.evaluate(fake(), False)[1]]

    # HSTS: real max-age, HTTPS only, same-host redirect fallback
    hsts = lambda v, url="https://a.com/": status_of(scanner._check_hsts, url=url, headers={"Strict-Transport-Security": v})
    assert status_of(scanner._check_hsts) == "FAIL"
    assert hsts("max-age=31536000; includeSubDomains") == "PASS"
    assert hsts("max-age=0") == "FAIL"
    assert hsts("max-age=3600") == "WARNING"
    assert hsts("includeSubDomains") == "FAIL"
    assert hsts("max-age=31536000", url="http://a.com/") == "FAIL"
    good = {"strict-transport-security": "max-age=31536000"}
    assert scanner._hsts_header(fake("https://a.com/home", history=[fake("https://a.com/", 301, good)])) == "max-age=31536000"
    assert scanner._hsts_header(fake("https://www.a.com/", history=[fake("https://a.com/", 301, good)])) == ""
    assert scanner._hsts_header(fake("https://a.com/", history=[fake("http://a.com/", 301, good)])) == ""

    # Framing: X-Frame-Options or CSP frame-ancestors
    assert status_of(scanner._check_framing) == "FAIL"
    assert status_of(scanner._check_framing, headers={"X-Frame-Options": "sameorigin"}) == "PASS"
    assert status_of(scanner._check_framing, headers={"X-Frame-Options": "ALLOW-FROM https://x.com"}) == "FAIL"
    assert status_of(scanner._check_framing, headers={"Content-Security-Policy": "frame-ancestors 'self'"}) == "PASS"
    assert status_of(scanner._check_framing, headers={"Content-Security-Policy": "frame-ancestors *"}) == "FAIL"

    # Cookies: separate Set-Cookie lines, Secure vs HttpOnly
    cookies = lambda *lines: status_of(scanner._check_cookies, headers=[("Set-Cookie", line) for line in lines])
    assert cookies() == "PASS"
    assert cookies("a=1; Secure; HttpOnly", "b=2; secure; httponly") == "PASS"
    assert cookies("a=1; Secure; HttpOnly", "b=2; Secure") == "WARNING"
    assert cookies("a=1; Secure; HttpOnly", "b=2; Path=/") == "FAIL"

    # Referrer-Policy: header, meta tag, last recognised token wins
    ref = lambda v: status_of(scanner._check_referrer, headers={"Referrer-Policy": v})
    assert status_of(scanner._check_referrer) == "WARNING"
    assert ref("strict-origin-when-cross-origin") == "PASS"
    assert ref("no-referrer, strict-origin-when-cross-origin") == "PASS"
    assert ref("no-referrer-when-downgrade") == "WARNING"
    assert ref("unsafe-url") == "FAIL"
    assert ref("nonsense") == "FAIL"
    assert status_of(scanner._check_referrer, text='<meta name="referrer" content="no-referrer">') == "PASS"

    # Permissions-Policy: must restrict a real feature
    perm = lambda v: status_of(scanner._check_permissions, headers={"Permissions-Policy": v})
    assert status_of(scanner._check_permissions) == "FAIL"
    assert perm('ch-dpr=(self "https://m.example"), ch-downlink=(self)') == "FAIL"  # amazon.in
    assert perm("camera=(), microphone=(), geolocation=(self)") == "PASS"
    assert perm("camera=*") == "FAIL"

    # Information disclosure: version numbers, not bare product names
    info = lambda **h: status_of(scanner._check_disclosure, headers=h)
    assert info() == "PASS"
    assert info(Server="cloudflare") == "PASS"
    assert info(Server="AmazonS3") == "PASS"
    assert info(Server="nginx/1.24.0") == "FAIL"
    assert info(Server="Apache 2.4.57") == "FAIL"
    assert info(**{"X-Powered-By": "Express"}) == "FAIL"

    # Scoring: PASS full weight, WARNING half, FAIL none; warnings rows are not scored
    assert sum(weight for _, weight, _, _ in scanner.CHECKS) == 100
    score, findings = scanner.evaluate(fake(status=403), ssl_warning=False)
    assert any(f["header_name"] == "Bot Protection" for f in findings)
    assert score == 25  # no cookies (15) + no version leak (5) + referrer default WARNING (10 // 2)
    perfect = fake(headers={
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    })
    assert scanner.evaluate(perfect, ssl_warning=False)[0] == 100

    # SSRF: internal addresses are refused (IP literals resolve without network access)
    for url in ("http://127.0.0.1", "http://10.0.0.5", "http://192.168.1.1", "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://0.0.0.0"):
        try:
            scanner.validate_url(url)
            raise AssertionError(f"{url} should be blocked")
        except scanner.InvalidURLError:
            pass
    assert scanner.is_public_host("8.8.8.8")

    # Rating bands: 80 / 60 / 40 boundaries
    assert [scanner.classify_risk(s) for s in (80, 79, 60, 59, 40, 39)] == [
        "Strong", "Moderate", "Moderate", "Weak", "Weak", "Minimal"]

    print("OK: scanner checks passed")


if __name__ == "__main__":
    main()
