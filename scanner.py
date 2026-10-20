"""Passive security header scanner. Implements docs/03_SECURITY_METHODOLOGY.md exactly."""
import ipaddress
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from types import SimpleNamespace
from urllib.parse import urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

NAVIGATION_TIMEOUT_MS = 10_000
# How long to let a JavaScript bot challenge (AWS WAF, Akamai, Cloudflare) resolve itself.
CHALLENGE_WAIT_SECONDS = 8

# The scan reads only the page's own response headers and HTML. Images and web fonts never change
# those, so skipping them saves CPU without changing any result. Scripts still run (bot challenges
# need them). --disable-dev-shm-usage avoids crashes in containers with a small /dev/shm.
# --disable-features=site-per-process,... keeps embedded sites (iframes) in the page's own process,
# which saved about 90 MB on YouTube. Site isolation protects a person's data across sites; these
# throwaway contexts hold none, and the main document the checks read is unaffected.
BROWSER_ARGS = [
    "--disable-dev-shm-usage", "--blink-settings=imagesEnabled=false", "--disable-remote-fonts",
    "--disable-features=site-per-process,IsolateOrigins",
]
# ponytail: Chromium is restarted every N scans to cap slow memory growth; tune if memory is tight.
BROWSER_RECYCLE_AFTER_SCANS = 50

# ponytail: vendor markers for the common bot walls (Akamai, Cloudflare, PerimeterX).
# Extend the tuple when a new one shows up; no generic "captcha" match, it false-positives.
BLOCK_STATUS_CODES = (403, 429, 503)
CHALLENGE_MARKERS = ("bm-verify", "/_sec/verify", "cf-chl", "challenge-platform", "px-captcha", "awswaf")
CHALLENGE_HEADERS = ("x-amzn-waf-action", "cf-mitigated")

MIN_HSTS_MAX_AGE = 15_552_000  # 180 days
STRONG_REFERRER_POLICIES = {
    "no-referrer", "same-origin", "origin", "strict-origin",
    "origin-when-cross-origin", "strict-origin-when-cross-origin",
}
WEAK_REFERRER_POLICIES = {"no-referrer-when-downgrade", "unsafe-url"}
# A version number such as "nginx/1.24.0" or "PHP 8.2"; bare names like "cloudflare" or "AmazonS3" do not match.
VERSION_PATTERN = re.compile(r"/\d|\d+\.\d+")


class ScanError(Exception):
    """The target could not be loaded."""


class InvalidURLError(ValueError):
    pass


SCAN_ERROR_HINTS = (
    ("Timeout", "The site took too long to respond. It may be slow or down right now; try again in a minute."),
    ("ERR_NAME_NOT_RESOLVED", "That domain could not be found. Check the spelling."),
    ("ERR_CONNECTION_REFUSED", "The site refused the connection. It may be down, or not serving that address."),
    ("ERR_CONNECTION_RESET", "The site closed the connection. It may be blocking automated visits."),
    ("ERR_CONNECTION_TIMED_OUT", "The site did not answer. It may be down or blocking automated visits."),
    ("ERR_HTTP2_PROTOCOL_ERROR", "The site rejected the browser connection. Some sites block automated visits."),
    ("ERR_CERT", "The site's HTTPS certificate could not be used, even with verification turned off."),
    ("ERR_SSL", "The site's HTTPS setup could not be negotiated."),
    ("private or internal", "The site redirected to a private or internal address, so it cannot be scanned."),
)


def describe_scan_error(error):
    """A plain-language reason for a failed scan, based on the browser's error text."""
    text = str(error)
    return next((hint for marker, hint in SCAN_ERROR_HINTS if marker in text),
                "Could not load that website. Check the address and that the site is up, then try again.")


def is_public_host(hostname):
    """True only if every address the host resolves to is on the public internet.

    Blocks SSRF: without this, a user could make the server fetch localhost, private
    networks (10.x, 192.168.x) or the cloud metadata address 169.254.169.254.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return False
    return all(ipaddress.ip_address(info[4][0].split("%")[0]).is_global for info in infos)


def validate_url(url):
    """Enforce http/https, a plausible domain, and a public (non-internal) address.

    An address typed without a scheme ("youtube.com") gets https:// added, as a browser would.
    """
    url = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise InvalidURLError("URL must start with http:// or https://")

    if not parsed.netloc:
        raise InvalidURLError("URL must include a host, e.g. https://example.com")

    hostname = parsed.hostname or ""
    if "." not in hostname:
        raise InvalidURLError(f"'{hostname}' does not look like a valid domain")

    if not is_public_host(hostname):
        raise InvalidURLError(
            f"'{hostname}' could not be resolved, or points to a private or internal address. Only public websites can be scanned."
        )

    return parsed.geturl()


def make_headers(pairs):
    """Case-insensitive header store that keeps repeated headers (Set-Cookie) separate."""
    headers = Message()
    for name, value in pairs:
        headers[name] = value
    return headers


def _snapshot(response, text=""):
    pairs = [(h["name"], h["value"]) for h in response.headers_array()]
    return SimpleNamespace(
        url=response.url, status_code=response.status,
        headers=make_headers(pairs), text=text, history=[],
    )


def _document_html(response):
    """The HTML exactly as the server sent it; empty if the body is unavailable (e.g. a redirect)."""
    try:
        return response.text()
    except PlaywrightError:
        return ""


def _load(browser, url, ignore_https_errors):
    # Headless Chromium identifies as "HeadlessChrome", and some sites (google.com) then omit
    # headers such as HSTS. Identify as the same Chrome version a real visitor would use.
    major = browser.version.split(".")[0]
    context = browser.new_context(
        ignore_https_errors=ignore_https_errors,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        ),
    )
    try:
        page = context.new_page()
        documents = []
        page.on(
            "response",
            lambda r: documents.append(r)
            if r.request.is_navigation_request() and r.frame == page.main_frame
            else None,
        )
        started = time.monotonic()
        page.goto(url, wait_until="commit", timeout=NAVIGATION_TIMEOUT_MS)
        # The headers and HTML the server sent, captured the moment the response arrives. If the page
        # then crashes or never finishes (YouTube can push Chromium past the 512 MB host), the scan
        # uses this instead of failing outright.
        server_only = _snapshot(documents[-1], _document_html(documents[-1]))
        server_only.history = [_snapshot(r) for r in documents[:-1]]  # redirects, read while the page is alive
        try:
            # Normal path, unchanged: let the page load within the same time limit and read the DOM,
            # which also catches settings scripts add (YouTube adds its referrer meta tag that way).
            remaining_ms = NAVIGATION_TIMEOUT_MS - (time.monotonic() - started) * 1000
            page.wait_for_load_state("domcontentloaded", timeout=max(remaining_ms, 1000))
        except PlaywrightError:  # crashed or did not finish in time
            final, partial = server_only, True
        else:
            partial = False
            try:
                body = page.content()
            except PlaywrightError:  # mid-navigation (e.g. reddit reloads itself right away), as before
                body = ""
            final = _snapshot(documents[-1], body)

        if not partial and detect_bot_challenge(final):
            # A challenge page reloads itself once its script passes, which adds a new
            # document response. Poll until the latest document is the real page.
            deadline = time.monotonic() + CHALLENGE_WAIT_SECONDS
            while True:
                try:
                    body = page.content()
                except PlaywrightError:  # mid-navigation
                    body = ""
                final = _snapshot(documents[-1], body)
                if not detect_bot_challenge(final) or time.monotonic() > deadline:
                    break
                page.wait_for_timeout(300)

        final.partial = partial
        if partial:
            return final
        final.history = [_snapshot(r) for r in documents[:-1]]
        return final
    finally:
        context.close()


# One Chromium stays running between scans, because launching it was most of a scan's time on the
# small hosting CPU. Every scan still gets a fresh browser context (no shared cookies or cache),
# so results are the same as with a new browser. All browser work runs on this single thread:
# Playwright's sync objects must stay on the thread that created them, and one thread also means
# one scan at a time, which keeps memory predictable.
_browser_thread = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scanner-browser")
_browser_state = {"playwright": None, "browser": None, "scans": 0}


def _get_browser():
    """Return the shared browser, (re)launching it if it is missing, crashed or due for a restart."""
    browser = _browser_state["browser"]
    if browser is not None and (not browser.is_connected() or _browser_state["scans"] >= BROWSER_RECYCLE_AFTER_SCANS):
        try:
            browser.close()
        except PlaywrightError:
            pass
        browser = _browser_state["browser"] = None
    if browser is None:
        if _browser_state["playwright"] is None:
            _browser_state["playwright"] = sync_playwright().start()
        browser = _browser_state["browser"] = _browser_state["playwright"].chromium.launch(headless=True, args=BROWSER_ARGS)
        _browser_state["scans"] = 0
    _browser_state["scans"] += 1
    return browser


def _fetch_on_browser_thread(url):
    started = time.perf_counter()
    try:
        browser = _get_browser()
        ready = time.perf_counter()
        try:
            result = _load(browser, url, ignore_https_errors=False), False
        except PlaywrightError as e:
            if "ERR_CERT" not in str(e):
                raise
            try:
                result = _load(browser, url, ignore_https_errors=True), True
            except PlaywrightError:
                # Some servers reset the first reconnect after the aborted strict handshake.
                result = _load(browser, url, ignore_https_errors=True), True
        done = time.perf_counter()
        print(f"scan timing: browser {ready - started:.2f}s, page {done - ready:.2f}s, url {url}", file=sys.stderr, flush=True)
        return result
    except (PlaywrightError, IndexError) as e:
        print(f"scan failed: {url}: {str(e).splitlines()[0] if str(e) else type(e).__name__}", file=sys.stderr, flush=True)
        browser = _browser_state["browser"]
        if browser is not None and not browser.is_connected():
            _browser_state["browser"] = None  # it crashed; launch a new one next scan
        raise ScanError(str(e).splitlines()[0] if str(e) else "no response received") from e


def fetch(url):
    """Load the target in headless Chromium and return its final document response.

    Falls back to ignoring certificate errors so self-signed targets still scan.
    """
    return _browser_thread.submit(_fetch_on_browser_thread, url).result()


def detect_bot_challenge(response):
    """Return a reason string if the response is a bot wall rather than the real page, else None."""
    if response.status_code in BLOCK_STATUS_CODES:
        return f"the server answered HTTP {response.status_code}"
    if any(name in response.headers for name in CHALLENGE_HEADERS):
        return "the server returned a WAF challenge instead of the site"
    body = response.text[:5000].lower()
    if any(marker in body for marker in CHALLENGE_MARKERS):
        return "the server returned a JavaScript bot-challenge page instead of the site"
    return None


def _hsts_header(response):
    """HSTS is host-scoped, so an earlier HTTPS hop on the final host counts.

    Other headers (CSP etc.) apply per document and are never merged from redirects.
    """
    final_host = urlparse(response.url).hostname
    for hop in [response] + response.history[::-1]:
        parsed = urlparse(hop.url)
        value = hop.headers.get("Strict-Transport-Security", "")
        if value and parsed.scheme == "https" and parsed.hostname == final_host:
            return value
    return ""


def _get_cookie_flags(response):
    """Return [{'name': str, 'secure': bool, 'httponly': bool}, ...] for each Set-Cookie header."""
    flags = []
    for line in response.headers.get_all("Set-Cookie", []):
        parts = [p.strip().lower() for p in line.split(";")]
        flags.append({
            "name": line.split("=", 1)[0].strip(),
            "secure": "secure" in parts,
            "httponly": "httponly" in parts,
        })
    return flags


def _csp_policies(headers):
    """One {directive: [sources]} dict per enforced CSP header. Report-Only is not enforced."""
    policies = []
    for policy in headers.get_all("Content-Security-Policy", []):
        directives = {}
        for part in policy.split(";"):
            tokens = part.split()
            if tokens:
                directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
        if directives:
            policies.append(directives)
    return policies


def _script_weaknesses(directives):
    """None if the policy does not restrict scripts, else the list of sources that undermine it."""
    sources = directives.get("script-src", directives.get("default-src"))
    if sources is None:
        return None
    strict = any(s == "'strict-dynamic'" or s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)
    weak = [] if "'strict-dynamic'" in sources else [s for s in sources if s in ("*", "http:", "https:", "data:")]
    if "'unsafe-inline'" in sources and not strict:
        weak.append("'unsafe-inline'")
    return weak


def _shown(value, limit=160):
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[:limit] + "..."


# Each check returns (status, severity, description). Recommendations and weights live in CHECKS.

def _check_csp(response):
    headers = response.headers
    policies = _csp_policies(headers)
    if not policies:
        if headers.get("Content-Security-Policy-Report-Only"):
            return "FAIL", "High", "Only a Content-Security-Policy-Report-Only header is sent. Report-only policies log violations but block nothing."
        return "FAIL", "High", "Content-Security-Policy header is missing."

    observed = _shown(" | ".join(headers.get_all("Content-Security-Policy", [])))
    # A page must satisfy every policy it is sent, so the strictest one decides.
    results = [w for w in map(_script_weaknesses, policies) if w is not None]
    if not results:
        return "FAIL", "High", f"A policy is sent but it has no script-src or default-src, so it does not restrict scripts and gives no XSS protection. Observed: {observed}"
    weak = min(results, key=len)
    if weak:
        return "WARNING", "Medium", f"Scripts are restricted, but the policy allows {', '.join(weak)}, which lets injected scripts run. Observed: {observed}"
    return "PASS", "Info", f"The policy restricts where scripts can load from. Observed: {observed}"


def _check_hsts(response):
    if urlparse(response.url).scheme != "https":
        return "FAIL", "High", "The final page is served over plain HTTP, so HSTS cannot apply."
    value = _hsts_header(response)
    if not value:
        return "FAIL", "High", "Strict-Transport-Security header is missing."
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    if not match:
        return "FAIL", "High", f"The header has no valid max-age directive. Observed: {_shown(value)}"
    max_age = int(match.group(1))
    if max_age == 0:
        return "FAIL", "High", "max-age is 0, which tells browsers to switch HSTS off."
    if max_age < MIN_HSTS_MAX_AGE:
        return "WARNING", "Medium", f"HSTS is on but max-age is only {max_age // 86400} days; at least 180 days is expected. Observed: {_shown(value)}"
    return "PASS", "Info", f"HSTS is enforced for {max_age // 86400} days. Observed: {_shown(value)}"


def _check_framing(response):
    xfo = response.headers.get("X-Frame-Options", "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        return "PASS", "Info", f"X-Frame-Options is set to {xfo}."
    ancestors = next(
        (p["frame-ancestors"] for p in _csp_policies(response.headers)
         if "frame-ancestors" in p and not any(s in ("*", "http:", "https:") for s in p["frame-ancestors"])),
        None,
    )
    if ancestors is not None:
        return "PASS", "Info", f"Framing is restricted by the CSP directive frame-ancestors {' '.join(ancestors)}, the modern replacement for X-Frame-Options."
    if xfo:
        return "FAIL", "Medium", f"X-Frame-Options has an invalid or obsolete value. Observed: {_shown(xfo)}"
    return "FAIL", "Medium", "Neither X-Frame-Options nor a CSP frame-ancestors directive restricts framing."


def _check_cookies(response):
    cookies = _get_cookie_flags(response)
    if not cookies:
        return "PASS", "Info", "The page sets no cookies."
    insecure = [c["name"] for c in cookies if not c["secure"]]
    script_readable = [c["name"] for c in cookies if not c["httponly"]]
    if insecure:
        return "FAIL", "High", f"{len(insecure)} of {len(cookies)} cookies lack the Secure flag and can be sent over plain HTTP: {_shown(', '.join(insecure))}"
    if script_readable:
        return "WARNING", "Medium", f"All cookies are Secure, but {len(script_readable)} of {len(cookies)} lack HttpOnly and are readable by JavaScript: {_shown(', '.join(script_readable))}"
    return "PASS", "Info", f"All {len(cookies)} cookies are marked Secure and HttpOnly."


def _check_nosniff(response):
    value = response.headers.get("X-Content-Type-Options", "").strip().lower()
    if value == "nosniff":
        return "PASS", "Info", "X-Content-Type-Options is set to nosniff."
    if value:
        return "FAIL", "Low", f"X-Content-Type-Options has an invalid value. Observed: {_shown(value)}"
    return "FAIL", "Low", "X-Content-Type-Options header is missing."


def _check_referrer(response):
    value = response.headers.get("Referrer-Policy", "")
    source = "header"
    if not value:
        meta = re.search(r"<meta[^>]+name=[\"']referrer[\"'][^>]*content=[\"']([^\"']+)", response.text, re.I)
        value, source = (meta.group(1), "meta tag") if meta else ("", "")
    if not value:
        return "WARNING", "Low", "No Referrer-Policy is set. Current browsers fall back to strict-origin-when-cross-origin, but older ones send the full URL."

    # Browsers use the last policy they recognise.
    tokens = [t.strip().lower() for t in value.split(",")]
    policy = next((t for t in reversed(tokens) if t in STRONG_REFERRER_POLICIES | WEAK_REFERRER_POLICIES), None)
    if policy in STRONG_REFERRER_POLICIES:
        return "PASS", "Info", f"Referrer-Policy is {policy} (set by {source})."
    if policy == "no-referrer-when-downgrade":
        return "WARNING", "Low", f"Referrer-Policy is {policy} (set by {source}), which still sends full URLs to other HTTPS sites."
    return "FAIL", "Low", f"Referrer-Policy is unsafe or unrecognised. Observed: {_shown(value)}"


def _check_permissions(response):
    value = response.headers.get("Permissions-Policy", "")
    if not value:
        return "FAIL", "Low", "Permissions-Policy header is missing."
    restricted = []
    for part in value.split(","):
        feature, _, allowlist = part.strip().partition("=")
        feature = feature.strip().lower()
        # ch-* entries delegate client hints; they do not restrict a browser feature.
        if feature and not feature.startswith("ch-") and "*" not in allowlist:
            restricted.append(feature)
    if restricted:
        return "PASS", "Info", f"{len(restricted)} browser features are restricted: {_shown(', '.join(restricted))}"
    return "FAIL", "Low", f"The header is sent but restricts no browser feature (camera, microphone, geolocation...). Observed: {_shown(value)}"


def _check_disclosure(response):
    headers = response.headers
    leaks = []
    server = headers.get("Server", "")
    if VERSION_PATTERN.search(server):
        leaks.append(f"Server: {server}")
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        if headers.get(name):
            leaks.append(f"{name}: {headers.get(name)}")
    if leaks:
        return "FAIL", "Medium", f"Headers reveal the underlying technology: {_shown('; '.join(leaks))}"
    return "PASS", "Info", "Server and X-Powered-By headers do not reveal specific software versions."


# (name, weight, check, recommendation). Weights are from docs/03_SECURITY_METHODOLOGY.md and total 100.
CHECKS = (
    ("Content-Security-Policy", 20, _check_csp, "Implement a strong Content-Security-Policy to restrict resource loading and mitigate Cross-Site Scripting (XSS) attacks."),
    ("Strict-Transport-Security", 15, _check_hsts, "Enforce HSTS with a sufficient max-age to ensure browsers only connect via HTTPS, preventing downgrade attacks."),
    ("X-Frame-Options", 15, _check_framing, "Configure X-Frame-Options to DENY or SAMEORIGIN to protect against clickjacking attacks."),
    ("Cookie Security", 15, _check_cookies, "Ensure all session cookies are marked with Secure, HttpOnly, and appropriately scoped SameSite attributes."),
    ("X-Content-Type-Options", 10, _check_nosniff, "Set X-Content-Type-Options to 'nosniff' to prevent browsers from MIME-sniffing the response."),
    ("Referrer-Policy", 10, _check_referrer, "Implement a strict Referrer-Policy to prevent leakage of sensitive URL paths to third-party sites."),
    ("Permissions-Policy", 10, _check_permissions, "Use Permissions-Policy to explicitly disable unnecessary browser features (like camera, microphone, geolocation)."),
    ("Information Disclosure", 5, _check_disclosure, "Remove or obscure the Server and X-Powered-By headers to minimize reconnaissance data available to attackers."),
)

WEIGHTS = {name: weight for name, weight, _check, _rec in CHECKS}
CHECKS_ORDER = [name for name, _weight, _check, _rec in CHECKS]

# Recommended header for each check that a single response header fixes.
RECOMMENDED_HEADERS = {
    "Content-Security-Policy": ("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
    "Strict-Transport-Security": ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    "X-Frame-Options": ("X-Frame-Options", "DENY"),
    "X-Content-Type-Options": ("X-Content-Type-Options", "nosniff"),
    "Referrer-Policy": ("Referrer-Policy", "strict-origin-when-cross-origin"),
    "Permissions-Policy": ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
}

# A typical line that fixes each check, shown on the results page and in the PDF.
FIX_EXAMPLES = {check: f"{name}: {value}" for check, (name, value) in RECOMMENDED_HEADERS.items()} | {
    "Cookie Security": "Set-Cookie: session=<value>; Secure; HttpOnly; SameSite=Lax; Path=/",
    "Information Disclosure": "nginx:   server_tokens off;\nApache:  ServerTokens Prod\nExpress: app.disable('x-powered-by')",
}

CSP_NOTE = (
    "Test the Content-Security-Policy first: it can block scripts your site needs.",
    "Send it as Content-Security-Policy-Report-Only until nothing breaks.",
)


def server_config(failing_checks):
    """Copy-paste config that adds every missing header at once, for nginx, Apache and Express.

    Returns {} when nothing needs fixing.
    """
    failing = [c for c in CHECKS_ORDER if c in failing_checks]
    headers = [RECOMMENDED_HEADERS[c] for c in failing if c in RECOMMENDED_HEADERS]
    hide_versions = "Information Disclosure" in failing
    cookies = "Cookie Security" in failing
    if not headers and not hide_versions and not cookies:
        return {}
    csp = "Content-Security-Policy" in failing

    nginx = ["# Inside your server { } block"]
    if csp:
        nginx += [f"# {line}" for line in CSP_NOTE]
    nginx += [f'add_header {name} "{value}" always;' for name, value in headers]
    if hide_versions:
        nginx.append("server_tokens off;")
    if cookies:
        nginx.append("# Cookies: add Secure; HttpOnly; SameSite=Lax where your application sets them.")

    apache = ["# In your VirtualHost (needs mod_headers: a2enmod headers)"]
    if csp:
        apache += [f"# {line}" for line in CSP_NOTE]
    apache += [f'Header always set {name} "{value}"' for name, value in headers]
    if hide_versions:
        apache += ["ServerSignature Off", "# In the main server config (httpd.conf), not a VirtualHost:", "ServerTokens Prod"]
    if cookies:
        apache.append("# Cookies: add Secure; HttpOnly; SameSite=Lax where your application sets them.")

    express = ["// Before your routes"]
    if csp:
        express += [f"// {line}" for line in CSP_NOTE]
    if hide_versions:
        express.append('app.disable("x-powered-by");')
    if headers:
        express.append("app.use((req, res, next) => {")
        express.append("  res.set({")
        express += [f'    "{name}": "{value}",' for name, value in headers]
        express += ["  });", "  next();", "});"]
    if cookies:
        express.append('// Cookies: res.cookie(name, value, { secure: true, httpOnly: true, sameSite: "lax" })')

    return {"nginx": "\n".join(nginx), "Apache": "\n".join(apache), "Express": "\n".join(express)}


def points_for(name, status):
    """Points a finding earned, or None for rows that are not scored (HTTPS, Bot Protection, SSL)."""
    weight = WEIGHTS.get(name)
    if weight is None:
        return None
    return {"PASS": weight, "WARNING": weight // 2}.get(status, 0)


def evaluate(response, ssl_warning):
    """Apply docs/03_SECURITY_METHODOLOGY.md. PASS earns the full weight, WARNING half, FAIL none."""
    findings = []
    score = 0
    for name, weight, check, recommendation in CHECKS:
        status, severity, description = check(response)
        score += points_for(name, status)
        findings.append({
            "header_name": name, "status": status, "severity": severity,
            "description": description,
            "recommendation": "No action needed." if status == "PASS" else recommendation,
        })

    if urlparse(response.url).scheme != "https":
        findings.append({
            "header_name": "HTTPS", "status": "WARNING", "severity": "High",
            "description": "The page is served over unencrypted HTTP. Anyone on the network path can read or alter it, which undermines every header above.",
            "recommendation": "Serve the site over HTTPS and redirect all HTTP requests to it.",
        })

    block_reason = detect_bot_challenge(response)
    if block_reason:
        findings.append({
            "header_name": "Bot Protection", "status": "WARNING", "severity": "High",
            "description": f"This scan did not reach the real page: {block_reason}. The score reflects the block page, not the site's actual configuration.",
            "recommendation": "Treat this score as unreliable. The challenge did not clear within the wait window; run the scan again, or check the headers manually in a browser.",
        })

    if getattr(response, "partial", False):
        findings.append({
            "header_name": "Page Load", "status": "WARNING", "severity": "Info",
            "description": "The page did not finish loading in time, so this result uses the headers and HTML the server sent. Settings that the page's own scripts add later (for example a referrer meta tag) are not included.",
            "recommendation": "Usually caused by a very heavy page. Run the scan again; if the note stays, treat checks that scripts can change as unverified.",
        })

    if ssl_warning:
        findings.append({
            "header_name": "SSL Certificate Validation", "status": "WARNING", "severity": "Medium",
            "description": "The target's SSL certificate could not be verified (e.g. self-signed or expired). The scan proceeded without verification.",
            "recommendation": "Use a certificate from a trusted Certificate Authority and ensure the chain is complete.",
        })

    return score, findings


def classify_risk(score):
    """Rates header hardening only, so the labels avoid claiming the site is vulnerable."""
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Weak"
    return "Minimal"


def scan(url):
    target_url = validate_url(url)
    response, ssl_warning = fetch(target_url)
    # A public site can redirect to an internal address. Refuse to report anything from such a chain.
    # ponytail: the browser has already sent that request; blocking it up front needs a filtering proxy.
    for hop in [response] + response.history:
        host = urlparse(hop.url).hostname
        if host and not is_public_host(host):
            raise ScanError(f"the site redirected to a private or internal address ({host})")
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
    print(f"Hardening:  {result['risk_level']}")
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
    except ScanError as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

    _print_report(result)
