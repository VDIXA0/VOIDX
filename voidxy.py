#!/usr/bin/env python3
"""
VOIDX - evidence-based OSINT & web security scanner (v2)

FOR AUTHORIZED TARGETS ONLY. Public targets require --authorized (or an
interactive confirmation). LAB mode refuses anything that is not a
loopback/private address.

Modes
  quick   DNS, TLS, homepage, headers, tech fingerprint, robots/security.txt/sitemap
  normal  + crawl (depth 2), forms, params, cookies, redirects, methods, exposed files
  deep    + deeper crawl, JS analysis, API discovery, CORS, error analysis
  lab     + non-destructive active checks (input reflection, TRACE), local/private only

Design rules
  * Every finding carries evidence, confidence, detection method and affected URLs.
  * Nothing is reported because a string "looks suspicious"; exposed-file checks
    validate content and are protected against soft-404 pages.
  * Findings with the same root cause are merged (one finding, many affected URLs).
  * No exploitation, no brute force, no destructive requests.

Dependencies: requests   (optional: python-whois)
"""
import argparse
import hashlib
import http.cookiejar
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib import robotparser
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("VOIDX needs the 'requests' package:  pip install requests")
try:
    import whois as _whois
except ImportError:
    _whois = None

VERSION = "2.0"
MAX_REDIRECTS = 8
BREAKER_THRESHOLD = 8
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONF_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4}
MODES = {"quick": 0, "normal": 1, "deep": 2, "lab": 3}
MODE_LIMITS = {"quick": (0, 1), "normal": (2, 50), "deep": (4, 200), "lab": (6, 1000)}
STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".woff", ".woff2",
              ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi", ".mov", ".webm", ".pdf", ".zip",
              ".gz", ".tar", ".rar", ".7z", ".exe", ".dmg", ".doc", ".docx", ".xls", ".xlsx",
              ".ppt", ".pptx", ".css", ".js", ".map")
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
             1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 11211, 27017]


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- helpers
def normalize(url):
    """Canonical form used for de-duplication. Returns None for unusable URLs."""
    try:
        if not url or len(url) > 2048:
            return None
        p = urlparse(url.strip())
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        host, port = p.hostname.lower().rstrip("."), p.port
    except ValueError:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        netloc += f":{port}"
    path = re.sub(r"/{2,}", "/", p.path or "/")
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunparse((p.scheme, netloc, path, "", query, ""))


def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def is_private_ip(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


def redact(value):
    return f"{value[:4]}…({len(value)} chars)" if len(value) > 8 else "***"


class BlockAll(http.cookiejar.CookiePolicy):
    """Scans are stateless: never store or replay cookies."""
    netscape = True
    rfc2965 = hide_cookie2 = False

    def set_ok(self, cookie, request): return False
    def return_ok(self, cookie, request): return False
    def domain_return_ok(self, domain, request): return False
    def path_return_ok(self, path, request): return False


# --------------------------------------------------------------------------- config/scope
@dataclass
class Config:
    target: str
    mode: str = "normal"
    max_depth: int = 2
    max_pages: int = 50
    max_bytes: int = 2_000_000
    timeout: float = 10.0
    delay: float = 0.2          # per-host delay between requests
    max_rps: float = 20.0       # global requests per second
    concurrency: int = 5
    retries: int = 2
    user_agent: str = f"VOIDX/{VERSION} (authorized security scan)"
    allow_subdomains: bool = False
    extra_domains: list = field(default_factory=list)
    respect_robots: bool = True
    ports: str = ""
    authorized: bool = False
    verify_tls: bool = True


class Scope:
    def __init__(self, host, allow_sub, extra):
        self.host, self.allow_sub = host, allow_sub
        self.extra = [e.lower().lstrip(".") for e in extra]
        self.target_private = False
        self._cache, self._lock = {}, threading.Lock()

    def allows(self, url):
        try:
            h = (urlparse(url).hostname or "").lower().rstrip(".")
        except ValueError:
            return False
        if not h:
            return False
        for base in [self.host] + self.extra:
            if h == base or (self.allow_sub and h.endswith("." + base)):
                return True
        return False

    def host_ok(self, host):
        """SSRF guard: a public target must never lead us to private addresses."""
        with self._lock:
            if host in self._cache:
                return self._cache[host]
        ips = resolve(host)
        ok = True if not ips or self.target_private else all(not is_private_ip(i) for i in ips)
        with self._lock:
            self._cache[host] = ok
        return ok


class Limiter:
    def __init__(self):
        self._next, self._lock = {}, threading.Lock()

    def wait(self, key, delay):
        if delay <= 0:
            return
        with self._lock:
            t = time.monotonic()
            start = max(t, self._next.get(key, 0))
            self._next[key] = start + delay
        if start > t:
            time.sleep(start - t)


# --------------------------------------------------------------------------- HTTP client
@dataclass
class Resp:
    url: str
    final_url: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0
    http_version: str = ""
    chain: list = field(default_factory=list)
    error: str = ""
    note: str = ""
    truncated: bool = False

    @property
    def content_type(self):
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


class Client:
    def __init__(self, cfg, scope):
        self.cfg, self.scope = cfg, scope
        self.s = requests.Session()
        self.s.cookies.set_policy(BlockAll())
        ad = requests.adapters.HTTPAdapter(pool_connections=cfg.concurrency,
                                           pool_maxsize=cfg.concurrency * 2, max_retries=0)
        self.s.mount("http://", ad)
        self.s.mount("https://", ad)
        self.s.headers.update({"User-Agent": cfg.user_agent, "Accept": "*/*"})
        self.limiter, self.fails = Limiter(), Counter()
        self.insecure, self.tls_errors = set(), {}
        self.stats, self.lock = Counter(), threading.Lock()

    def fetch(self, url, method="GET", headers=None):
        chain, seen, cur = [], {url}, url
        for _ in range(MAX_REDIRECTS + 1):
            if not self.scope.allows(cur):
                return Resp(url, cur, error="blocked: out of scope", chain=chain)
            r = self._request(cur, method, headers)
            r.url = url
            if r.error:
                r.chain = chain
                return r
            loc = r.headers.get("location")
            if r.status in (301, 302, 303, 307, 308) and loc:
                nxt = normalize(urljoin(cur, loc))
                chain.append({"url": cur, "status": r.status, "location": nxt or loc})
                if not nxt:
                    r.error, r.chain = "invalid redirect target", chain
                    return r
                if nxt in seen:
                    r.error, r.chain = "redirect loop", chain
                    return r
                if not self.scope.allows(nxt):
                    r.note, r.chain = f"redirects out of scope: {nxt}", chain
                    return r
                seen.add(nxt)
                cur = nxt
                continue
            r.chain = chain
            return r
        return Resp(url, cur, error="too many redirects", chain=chain)

    def _request(self, url, method, headers):
        cfg, host, last = self.cfg, urlparse(url).hostname, ""
        if not self.scope.host_ok(host):
            return Resp(url, url, error="blocked: host resolves to a non-public address")
        for attempt in range(cfg.retries + 1):
            if self.fails[host] >= BREAKER_THRESHOLD:
                return Resp(url, url, error="circuit breaker open for host")
            self.limiter.wait("*", 1.0 / cfg.max_rps)
            self.limiter.wait(host, cfg.delay)
            verify = cfg.verify_tls and host not in self.insecure
            t0 = time.monotonic()
            try:
                with self.s.request(method, url, headers=headers, timeout=(cfg.timeout, cfg.timeout),
                                    allow_redirects=False, stream=True, verify=verify) as resp:
                    chunks, n, trunc = [], 0, False
                    if method not in ("HEAD", "OPTIONS", "TRACE") or method == "TRACE":
                        for c in resp.iter_content(16384):
                            n += len(c)
                            chunks.append(c)
                            if n > cfg.max_bytes or time.monotonic() - t0 > cfg.timeout * 3:
                                trunc = True
                                break
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    raw = resp.raw.headers
                    sc = raw.getlist("Set-Cookie") if hasattr(raw, "getlist") else \
                        ([hdrs["set-cookie"]] if "set-cookie" in hdrs else [])
                    ver = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(resp.raw, "version", 0), "unknown")
                    r = Resp(url, url, resp.status_code, hdrs, sc, b"".join(chunks),
                             time.monotonic() - t0, ver, truncated=trunc)
                with self.lock:
                    self.stats["requests"] += 1
                    self.stats["bytes"] += len(r.body)
                if r.status in (429, 503) and attempt < cfg.retries:
                    ra = hdrs.get("retry-after", "")
                    time.sleep(min(float(ra) if ra.isdigit() else 2 ** attempt, 30))
                    with self.lock:
                        self.stats["retries"] += 1
                    continue
                with self.lock:
                    self.fails[host] = 0
                return r
            except requests.exceptions.SSLError as e:
                with self.lock:
                    self.tls_errors[host] = str(e)[:300]
                if verify:
                    self.insecure.add(host)   # keep scanning; the TLS problem is reported separately
                    continue
                last = f"TLS error: {str(e)[:150]}"
                break
            except requests.exceptions.Timeout:
                last = "timeout"
            except requests.exceptions.ConnectionError as e:
                last = f"connection error: {str(e)[:150]}"
            except Exception as e:  # never let one resource kill the scan
                last = f"{type(e).__name__}: {str(e)[:150]}"
            with self.lock:
                self.fails[host] += 1
                self.stats["retries"] += 1
            time.sleep(min(0.5 * 2 ** attempt, 8))
        with self.lock:
            self.stats["failed_requests"] += 1
        return Resp(url, url, error=last or "request failed")


# --------------------------------------------------------------------------- HTML parsing
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.refs, self.forms, self.comments, self.inline_js = [], [], [], []
        self.canonical = self.generator = None
        self.markers = set()
        self._form, self._in_script, self._buf = None, False, []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for m in ("ng-version", "data-reactroot", "data-v-app", "data-server-rendered"):
            if m in a:
                self.markers.add((m, a[m]))
        if tag == "a" and a.get("href"):
            self.refs.append(("link", a["href"]))
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if "canonical" in rel:
                self.canonical = a["href"]
                self.refs.append(("canonical", a["href"]))
            else:
                self.refs.append(("css" if "stylesheet" in rel else "link-rel", a["href"]))
        elif tag == "script":
            if a.get("src"):
                self.refs.append(("script", a["src"]))
            else:
                self._in_script, self._buf = True, []
        elif tag in ("img", "source", "video", "audio", "embed", "iframe") and a.get("src"):
            self.refs.append(("iframe" if tag == "iframe" else "asset", a["src"]))
        elif tag == "meta":
            name = (a.get("name") or a.get("property")).lower() if (a.get("name") or a.get("property")) else ""
            if name == "generator":
                self.generator = a.get("content", "")
            elif name == "og:url" and a.get("content"):
                self.refs.append(("opengraph", a["content"]))
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form["inputs"].append({"name": a["name"], "type": a.get("type", "text") if tag == "input" else tag})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "script" and self._in_script:
            self.inline_js.append("".join(self._buf)[:200000])
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_comment(self, data):
        if len(self.comments) < 50:
            self.comments.append(data.strip()[:300])


# --------------------------------------------------------------------------- findings
@dataclass
class Finding:
    id: str
    rule: str
    title: str
    severity: str
    confidence: str
    detection: str
    cwe: str
    owasp: str
    parameter: str
    evidence: list
    reason: str
    remediation: str
    references: list
    affected: list
    occurrences: int
    timestamp: str


class Findings:
    def __init__(self):
        self.items = {}

    def add(self, rule, title, sev, conf, url, evidence, reason, fix, cwe="", owasp="",
            param="", refs=(), key="", method="passive analysis"):
        k = (rule, key)
        if k in self.items:
            f = self.items[k]
            f.occurrences += 1
            if url and url not in f.affected and len(f.affected) < 50:
                f.affected.append(url)
            if evidence and evidence not in f.evidence and len(f.evidence) < 5:
                f.evidence.append(evidence)
            return f
        fid = "VX-" + hashlib.sha1(repr(k).encode()).hexdigest()[:8].upper()
        f = Finding(fid, rule, title, sev, conf, method, cwe, owasp, param, [evidence] if evidence else [],
                    reason, fix, list(refs), [url] if url else [], 1, now())
        self.items[k] = f
        return f

    def sorted(self):
        return sorted(self.items.values(),
                      key=lambda f: (-SEV_RANK[f.severity], -CONF_RANK[f.confidence], f.title))


HEADER_RULES = {
    "content-security-policy": ("Content-Security-Policy header not set", "low", "CWE-693",
                                "A05:2021 Security Misconfiguration",
                                "Define a restrictive Content-Security-Policy.",
                                ["https://developer.mozilla.org/docs/Web/HTTP/CSP"]),
    "strict-transport-security": ("Strict-Transport-Security header not set on HTTPS responses", "low",
                                  "CWE-319", "A05:2021 Security Misconfiguration",
                                  "Send Strict-Transport-Security with a max-age of at least 6 months.",
                                  ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]),
    "x-content-type-options": ("X-Content-Type-Options: nosniff not set", "low", "CWE-693",
                               "A05:2021 Security Misconfiguration", "Send X-Content-Type-Options: nosniff.",
                               ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"]),
    "x-frame-options": ("No clickjacking protection (X-Frame-Options / frame-ancestors)", "low", "CWE-1021",
                        "A05:2021 Security Misconfiguration",
                        "Send X-Frame-Options or a CSP frame-ancestors directive.",
                        ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"]),
    "referrer-policy": ("Referrer-Policy header not set", "info", "CWE-200",
                        "A05:2021 Security Misconfiguration", "Send a Referrer-Policy such as strict-origin-when-cross-origin.",
                        ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"]),
    "permissions-policy": ("Permissions-Policy header not set", "info", "CWE-693",
                           "A05:2021 Security Misconfiguration", "Send a Permissions-Policy limiting unused browser features.",
                           ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"]),
}

# path, validator, title, severity, confidence, CWE, remediation
def _kv(t): return bool(re.search(r"^[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S+", t, re.M)) and "<html" not in t.lower()[:500]
EXPOSED_FILES = [
    ("/.git/HEAD", lambda r: r.text.startswith("ref:"), "Git repository metadata exposed", "high", "confirmed", "CWE-538"),
    ("/.git/config", lambda r: "[core]" in r.text, "Git configuration exposed", "high", "confirmed", "CWE-538"),
    ("/.env", lambda r: _kv(r.text), "Environment file (.env) exposed", "high", "high", "CWE-538"),
    ("/.DS_Store", lambda r: r.body.startswith(b"\x00\x00\x00\x01Bud1"), "macOS .DS_Store file exposed", "low", "confirmed", "CWE-538"),
    ("/.htaccess", lambda r: "RewriteEngine" in r.text or "AuthType" in r.text, "Apache .htaccess file readable", "low", "high", "CWE-538"),
    ("/phpinfo.php", lambda r: "PHP Version" in r.text and "phpinfo" in r.text.lower(), "phpinfo() page exposed", "medium", "confirmed", "CWE-200"),
    ("/info.php", lambda r: "PHP Version" in r.text and "phpinfo" in r.text.lower(), "phpinfo() page exposed", "medium", "confirmed", "CWE-200"),
    ("/server-status", lambda r: "Apache Server Status" in r.text, "Apache server-status exposed", "medium", "confirmed", "CWE-200"),
    ("/actuator/env", lambda r: "propertySources" in r.text, "Spring Boot /actuator/env exposed", "high", "confirmed", "CWE-200"),
    ("/console", lambda r: "Werkzeug" in r.text and "console" in r.text.lower() and "<html" in r.text.lower(), "Werkzeug debug console exposed", "high", "high", "CWE-489"),
    ("/WEB-INF/web.xml", lambda r: "<web-app" in r.text, "WEB-INF/web.xml exposed", "high", "confirmed", "CWE-538"),
    ("/composer.json", lambda r: r.text.lstrip().startswith("{") and '"require"' in r.text, "composer.json exposed", "info", "confirmed", "CWE-200"),
    ("/package.json", lambda r: r.text.lstrip().startswith("{") and '"dependencies"' in r.text, "package.json exposed", "info", "confirmed", "CWE-200"),
    ("/wp-config.php.bak", lambda r: "DB_PASSWORD" in r.text, "WordPress config backup exposed", "high", "confirmed", "CWE-530"),
    ("/wp-config.php~", lambda r: "DB_PASSWORD" in r.text, "WordPress config backup exposed", "high", "confirmed", "CWE-530"),
    ("/config.php.bak", lambda r: "<?php" in r.text, "PHP config backup exposed", "high", "high", "CWE-530"),
    ("/backup.zip", lambda r: r.body[:4] == b"PK\x03\x04", "Backup archive exposed", "high", "confirmed", "CWE-530"),
    ("/site.zip", lambda r: r.body[:4] == b"PK\x03\x04", "Backup archive exposed", "high", "confirmed", "CWE-530"),
    ("/backup.sql", lambda r: bool(re.search(r"CREATE TABLE|INSERT INTO", r.text)), "SQL dump exposed", "high", "confirmed", "CWE-530"),
    ("/dump.sql", lambda r: bool(re.search(r"CREATE TABLE|INSERT INTO", r.text)), "SQL dump exposed", "high", "confirmed", "CWE-530"),
]
API_DOC_PATHS = ["/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
                 "/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json"]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]
AUTH_PATHS = ["/login", "/signin", "/admin", "/administrator", "/wp-login.php", "/user/login", "/account/login"]
ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace", "medium"),
    (r"You're seeing this error because you have <code>DEBUG = True</code>", "Django DEBUG mode page", "high"),
    (r"\b(?:Warning|Fatal error|Parse error|Notice)</b>:\s.{0,200}\bon line\b", "PHP error message", "medium"),
    (r"\bat [\w.$]+\([\w]+\.java:\d+\)", "Java stack trace", "medium"),
    (r"Whitelabel Error Page", "Spring Boot default error page", "low"),
    (r"Server Error in '/' Application", "ASP.NET detailed error page", "medium"),
    (r"You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}:", "Database error message", "medium"),
]
SECRET_PATTERNS = [
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private key block", "high", "high"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key ID (format match)", "medium", "medium"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36}\b", "GitHub token (format match)", "medium", "medium"),
    (r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "Slack token (format match)", "medium", "medium"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JSON Web Token", "low", "medium"),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key (often intentionally public)", "info", "low"),
]
GENERIC_SECRET = re.compile(r"""(?i)\b(api[_-]?key|secret|passwd|password|access[_-]?token)\b["']?\s*[:=]\s*["']([^"'\s]{8,64})["']""")
PLACEHOLDER = re.compile(r"(?i)(your|example|changeme|placeholder|xxxx|\*{4}|<.*>|test|sample|dummy|0000)")


# --------------------------------------------------------------------------- scanner
class Scanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.level = MODES[cfg.mode]
        self.host = urlparse(cfg.target if "//" in cfg.target else "//" + cfg.target).hostname.lower()
        self.scope = Scope(self.host, cfg.allow_subdomains, cfg.extra_domains)
        self.client = Client(cfg, self.scope)
        self.findings = Findings()
        self.endpoints, self.params, self.api, self.auth = {}, {}, {}, []
        self.tech, self.external, self.errors, self.timeline = {}, set(), [], []
        self.http_samples, self.cookies_seen, self.js_findings = [], {}, []
        self.js_endpoints, self.emails, self.subdomains, self.ips = {}, {}, set(), []
        self.osint, self.tls, self.ports_result, self.robots = {}, {}, [], None
        self.header_stats = {h: Counter() for h in HEADER_RULES}
        self.pattern_count, self.frontier, self.base, self.baseline = Counter(), [], None, None
        self.graph, self.start = [], time.time()
        self.js_seen = set()

    # ---- utilities
    def log(self, msg):
        self.timeline.append({"time": now(), "event": msg})
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def add_tech(self, name, evidence, weight=1.0, version=None):
        key = name.lower()
        t = self.tech.setdefault(key, {"name": name, "version": None, "weight": 0.0, "evidence": []})
        t["weight"] += weight
        if evidence not in t["evidence"]:
            t["evidence"].append(evidence)
        if version and not t["version"]:
            t["version"] = version

    def add_param(self, endpoint, method, name, source, ptype, user_controlled=True):
        k = (endpoint, method, name)
        if k not in self.params and len(self.params) < 3000:
            self.params[k] = {"parameter": name, "endpoint": endpoint, "method": method, "source": source,
                              "type": ptype, "user_controlled": user_controlled}

    def add_endpoint(self, url, source, method, depth, base=None, crawl=True):
        if base:
            url = urljoin(base, url.strip())
        n = normalize(url)
        if not n:
            return None
        if not self.scope.allows(n):
            if len(self.external) < 500:
                self.external.add(n)
            return None
        if n in self.endpoints:
            return self.endpoints[n]
        p = urlparse(n)
        if p.query:
            for k, _ in parse_qsl(p.query, keep_blank_values=True):
                self.add_param(n, "GET", k, source, "query")
            self.pattern_count[(p.netloc, p.path)] += 1
            if self.pattern_count[(p.netloc, p.path)] > 8:   # crawl-trap guard
                return None
        ep = {"url": n, "source": source, "discovery_method": method, "depth": depth, "status": None,
              "content_type": None, "timestamp": now(), "state": "DISCOVERED", "kind": "page"}
        if p.path.lower().endswith(STATIC_EXT):
            ep["kind"] = "script" if p.path.lower().endswith(".js") else "asset"
        self.endpoints[n] = ep
        if p.hostname != self.host and p.hostname.endswith("." + self.host):
            self.subdomains.add(p.hostname)
        if crawl and ep["kind"] == "page" and depth <= self.cfg.max_depth:
            if self.cfg.respect_robots and self.robots and not self.robots.can_fetch("*", n):
                ep["state"] = "SKIPPED (robots.txt)"
            else:
                ep["state"] = "QUEUED"
                self.frontier.append(ep)
        return ep

    # ---- phase 1: target, DNS, TLS
    def discover_target(self):
        self.ips = resolve(self.host)
        if not self.ips:
            self.log(f"DNS resolution failed for {self.host}")
            self.errors.append({"resource": self.host, "error": "DNS resolution failed"})
            return False
        self.log(f"DNS: {self.host} -> {', '.join(self.ips)}")
        self.scope.target_private = all(is_private_ip(i) for i in self.ips)
        try:
            self.osint["reverse_dns"] = {ip: socket.gethostbyaddr(ip)[0] for ip in self.ips[:3]}
        except (socket.herror, socket.gaierror, OSError):
            self.osint["reverse_dns"] = {}
        if _whois and not re.fullmatch(r"[\d.:]+", self.host):
            try:
                w = _whois.whois(self.host)
                cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                self.osint["whois"] = {"registrar": w.registrar, "created": str(cd) if cd else None,
                                       "expires": str(w.expiration_date), "name_servers": w.name_servers,
                                       "org": w.org, "country": w.country}
            except Exception as e:
                self.osint["whois"] = {"error": f"lookup failed: {type(e).__name__}"}
        return True

    def tls_probe(self, port=443):
        info = {"port": port}
        for verify in (True, False):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            try:
                with socket.create_connection((self.host, port), timeout=self.cfg.timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=self.host) as ss:
                        info.update(protocol=ss.version(), cipher=ss.cipher()[0], verified=verify)
                        if verify:
                            c = ss.getpeercert()
                            info["subject"] = dict(x[0] for x in c.get("subject", ()))
                            info["issuer"] = dict(x[0] for x in c.get("issuer", ()))
                            info["not_after"] = c.get("notAfter")
                            sans = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
                            info["san"] = sans
                            for s_ in sans:
                                s_ = s_.lstrip("*.").lower()
                                if s_.endswith("." + self.host) and s_ != self.host:
                                    self.subdomains.add(s_)
                            if c.get("notAfter"):
                                days = (datetime.fromtimestamp(ssl.cert_time_to_seconds(c["notAfter"]), timezone.utc)
                                        - datetime.now(timezone.utc)).days
                                info["days_remaining"] = days
                                if days < 30:
                                    self.findings.add("tls.expiring", "TLS certificate expires within 30 days", "low", "confirmed",
                                                      f"https://{self.host}:{port}", f"notAfter={c['notAfter']} ({days} days)",
                                                      "Certificate expiry observed in the TLS handshake.", "Renew the certificate.",
                                                      "CWE-298", "A02:2021 Cryptographic Failures", method="TLS handshake")
                        if not verify:
                            err = self.client.tls_errors.get(self.host, "certificate validation failed")
                            info["verify_error"] = err
                            self.findings.add("tls.untrusted", "TLS certificate failed validation", "medium", "high",
                                              f"https://{self.host}:{port}", err[:200],
                                              "The default trust store rejected the presented certificate (expired, self-signed, "
                                              "wrong hostname or untrusted CA).", "Install a certificate from a trusted CA that matches the hostname.",
                                              "CWE-295", "A02:2021 Cryptographic Failures", method="TLS handshake")
                        return info
            except ssl.SSLError as e:
                info["verify_error"] = str(e)[:200]
                if not verify:
                    info["error"] = str(e)[:200]
                    return info
            except (OSError, socket.timeout) as e:
                info["error"] = f"{type(e).__name__}: {str(e)[:120]}"
                return info
        return info

    # ---- phase 2: homepage / robots / sitemap
    def choose_base(self):
        raw = self.cfg.target
        if "//" not in raw:
            candidates = [f"https://{raw}", f"http://{raw}"]
        else:
            candidates = [raw]
        for c in candidates:
            n = normalize(c)
            r = self.client.fetch(n)
            if not r.error:
                self.base = n
                return r
            self.errors.append({"resource": n, "error": r.error})
        return None

    def analyze_http(self, r):
        h, https = r.headers, r.final_url.startswith("https://")
        ct = r.content_type
        html = "html" in ct
        if 200 <= r.status < 300:
            csp = h.get("content-security-policy", "")
            for name in HEADER_RULES:
                needed = (name != "strict-transport-security" or https)
                needed = needed and (html or name in ("strict-transport-security", "x-content-type-options"))
                if not needed:
                    continue
                present = name in h
                if name == "x-frame-options" and "frame-ancestors" in csp:
                    present = True
                if name == "x-content-type-options" and h.get(name, "").lower() != "nosniff":
                    present = False
                self.header_stats[name]["present" if present else "missing"] += 1
                if not present:
                    t, sev, cwe, owasp, fix, refs = HEADER_RULES[name]
                    self.findings.add(f"hdr.{name}", t, sev, "high", r.final_url, f"header absent in response ({r.status})",
                                      "Missing hardening header observed directly in the response; severity is limited because "
                                      "impact depends on the application.", fix, cwe, owasp, refs=refs,
                                      method="response header analysis")
            if csp and re.search(r"(script-src|default-src)[^;]*('unsafe-inline'|\*)", csp):
                self.findings.add("hdr.csp-weak", "Content-Security-Policy allows unsafe script sources", "low", "medium",
                                  r.final_url, csp[:160], "'unsafe-inline' or wildcard in script-src/default-src weakens XSS mitigation.",
                                  "Use nonces or hashes instead of 'unsafe-inline'.", "CWE-693", "A05:2021 Security Misconfiguration",
                                  method="CSP parsing")
            sts = h.get("strict-transport-security", "")
            m = re.search(r"max-age=(\d+)", sts)
            if https and m and int(m.group(1)) < 15552000:
                self.findings.add("hdr.hsts-short", "HSTS max-age shorter than 6 months", "info", "high", r.final_url, sts,
                                  "Short HSTS lifetime reduces protection.", "Raise max-age to at least 15552000.",
                                  "CWE-319", "A05:2021 Security Misconfiguration", method="response header analysis")
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            v = h.get(name)
            if not v:
                continue
            for i, m in enumerate(re.finditer(r"([A-Za-z][\w\-.]*)(?:/(\d[\w.\-]*))?", re.sub(r"\(.*?\)", "", v))):
                if i == 0 or m.group(2):
                    self.add_tech(m.group(1), f"{name}: {v}", 1.0, m.group(2))
            if re.search(r"/\d", v):
                self.findings.add("info.version-header", "Software version disclosed in HTTP headers", "info", "high",
                                  r.final_url, f"{name}: {v}",
                                  "Exact versions help attackers match known vulnerabilities. VOIDX does not judge whether the "
                                  "version is outdated (no CVE database is bundled).", "Suppress version details in server banners.",
                                  "CWE-200", "A05:2021 Security Misconfiguration", key=f"{name}:{v}", method="response header analysis")
        for c in r.set_cookies:
            self.analyze_cookie(c, r)
            nm = c.split("=", 1)[0].strip()
            for pat, tname in (("PHPSESSID", "PHP"), ("JSESSIONID", "Java Servlet"), ("csrftoken", "Django"),
                               ("laravel_session", "Laravel"), ("connect.sid", "Express"),
                               ("ASP.NET_SessionId", "ASP.NET")):
                if nm == pat:
                    self.add_tech(tname, f"cookie {nm}", 0.7)
        if r.chain:
            self.osint.setdefault("redirects", [])
            if len(self.osint["redirects"]) < 50:
                self.osint["redirects"].append({"from": r.url, "chain": r.chain, "final": r.final_url})
        if len(self.http_samples) < 500:
            self.http_samples.append({
                "url": r.final_url, "status": r.status, "http_version": r.http_version,
                "content_type": r.content_type, "content_length": len(r.body),
                "response_time_ms": int(r.elapsed * 1000), "server": h.get("server"),
                "compression": h.get("content-encoding"), "cache_control": h.get("cache-control"),
                "etag": bool(h.get("etag")), "redirect_hops": len(r.chain), "truncated": r.truncated})

    def analyze_cookie(self, raw, r):
        parts = [x.strip() for x in raw.split(";")]
        name, _, _ = parts[0].partition("=")
        attrs = {p.partition("=")[0].lower(): p.partition("=")[2] for p in parts[1:]}
        https = r.final_url.startswith("https://")
        session_like = bool(re.search(r"(?i)sess|sid|auth|token|jwt|login", name))
        self.cookies_seen[name] = {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
                                   "samesite": attrs.get("samesite"), "session_like": session_like,
                                   "domain": attrs.get("domain"), "path": attrs.get("path"), "seen_on": r.final_url}
        base = {"cwe": "CWE-614", "owasp": "A05:2021 Security Misconfiguration", "key": name, "method": "Set-Cookie parsing"}
        if https and "secure" not in attrs:
            self.findings.add("cookie.secure", f"Cookie '{name}' set without Secure flag", "medium" if session_like else "low",
                              "high", r.final_url, f"Set-Cookie: {name}=…; flags={sorted(attrs)}",
                              "Cookie may be sent over plain HTTP." + (" Name suggests a session/auth cookie." if session_like else ""),
                              "Add the Secure attribute.", **base)
        if "httponly" not in attrs:
            base2 = dict(base, cwe="CWE-1004")
            self.findings.add("cookie.httponly", f"Cookie '{name}' set without HttpOnly flag", "medium" if session_like else "low",
                              "high", r.final_url, f"Set-Cookie: {name}=…; flags={sorted(attrs)}",
                              "Cookie is readable by JavaScript." + (" Name suggests a session/auth cookie." if session_like else ""),
                              "Add the HttpOnly attribute.", **base2)
        ss = attrs.get("samesite", "").lower()
        if ss == "none" and "secure" not in attrs:
            self.findings.add("cookie.samesite-none", f"Cookie '{name}' uses SameSite=None without Secure", "medium", "high",
                              r.final_url, "SameSite=None without Secure", "Browsers reject or mishandle this combination.",
                              "Add Secure or use SameSite=Lax/Strict.", **dict(base, cwe="CWE-1275"))
        elif not ss:
            self.findings.add("cookie.samesite", f"Cookie '{name}' has no SameSite attribute", "info", "high", r.final_url,
                              "no SameSite attribute", "Modern browsers default to Lax; explicit is clearer.",
                              "Set SameSite=Lax or Strict.", **dict(base, cwe="CWE-1275"))

    def analyze_body(self, ep, r):
        url, text, ct = r.final_url, r.text, r.content_type
        if re.search(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /", text[:5000], re.I):
            self.findings.add("disclosure.dirlist", "Directory listing enabled", "medium", "high", url,
                              "page body is an auto-generated index", "The server lists directory contents.",
                              "Disable directory indexing (Apache: Options -Indexes; nginx: autoindex off).",
                              "CWE-548", "A05:2021 Security Misconfiguration", method="body pattern match", key=url)
        if self.level >= 2 or r.status >= 500:
            for pat, label, conf in ERROR_PATTERNS:
                m = re.search(pat, text)
                if m:
                    sev = "high" if conf == "high" else "low" if label.startswith("Spring") else "medium"
                    self.findings.add("disclosure.error", f"Verbose error / debug output: {label}", sev, conf, url,
                                      f"HTTP {r.status}: {m.group(0)[:100]!r}", "Application internals are returned to clients.",
                                      "Disable debug mode and return generic error pages.", "CWE-209",
                                      "A05:2021 Security Misconfiguration", key=label, method="body pattern match")
                    break
        if url.startswith("https://") and "html" in ct:
            pass
        for e in set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text[:300000])):
            if len(self.emails) < 200:
                self.emails.setdefault(e.lower(), url)
        ctx = text[:300000]
        sigs = [(r"wp-content/|wp-includes/", "WordPress", 1.0), (r"__NEXT_DATA__|/_next/static", "Next.js", 1.0),
                (r"Drupal\.settings|/sites/default/files", "Drupal", 0.8), (r"/media/jui/|Joomla!", "Joomla", 0.8),
                (r"react(?:\.production|-dom)", "React", 0.6), (r"vue(?:\.runtime)?(?:\.min)?\.js", "Vue", 0.6),
                (r"csrfmiddlewaretoken", "Django", 0.7), (r"cdn\.shopify\.com", "Shopify", 0.8)]
        for pat, name, w in sigs:
            if re.search(pat, ctx):
                self.add_tech(name, f"HTML/asset pattern on {url}", w)
        for m in re.finditer(r"jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", ctx, re.I):
            self.add_tech("jQuery", f"script filename {m.group(0)}", 0.8, m.group(1))

    def analyze_html(self, ep, r):
        p = PageParser()
        try:
            p.feed(r.text[:self.cfg.max_bytes])
        except Exception as e:
            self.errors.append({"resource": r.final_url, "error": f"malformed HTML: {type(e).__name__}"})
        base, depth = r.final_url, ep["depth"] + 1
        if p.generator:
            m = re.match(r"([A-Za-z][\w .\-]*?)\s+v?(\d[\w.\-]*)?$", p.generator.strip())
            self.add_tech(m.group(1) if m else p.generator, f"meta generator: {p.generator}", 1.0, m.group(2) if m else None)
        for mk, val in p.markers:
            if mk == "ng-version":
                self.add_tech("Angular", f"ng-version={val}", 1.0, val)
            elif mk == "data-reactroot":
                self.add_tech("React", "data-reactroot attribute", 0.8)
            elif mk.startswith("data-v-") or mk == "data-v-app":
                self.add_tech("Vue", f"{mk} attribute", 0.8)
        for kind, href in p.refs:
            href = href.strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                if href.startswith("mailto:") and len(self.emails) < 200:
                    self.emails.setdefault(href[7:].split("?")[0].lower(), r.final_url)
                continue
            full = urljoin(base, href)
            if kind in ("link", "iframe", "canonical", "opengraph", "link-rel"):
                self.add_endpoint(full, r.final_url, f"html:{kind}", depth)
            else:
                self.add_endpoint(full, r.final_url, f"html:{kind}", depth, crawl=False)
            if base.startswith("https://") and full.startswith("http://") and kind in ("script", "css", "iframe", "asset"):
                active = kind in ("script", "css", "iframe")
                self.findings.add("mixed." + ("active" if active else "passive"),
                                  "Mixed content: HTTP " + ("scripts/styles/frames" if active else "images/media") + " on HTTPS page",
                                  "medium" if active else "low", "high", r.final_url, f"{kind} -> {full[:120]}",
                                  "HTTPS page loads sub-resources over plain HTTP.", "Load all resources over HTTPS.",
                                  "CWE-311", "A02:2021 Cryptographic Failures", key=kind, method="HTML parsing")
        for form in p.forms:
            action = urljoin(base, form["action"]) if form["action"] else r.final_url
            m = form["method"].upper() if form["method"] in ("get", "post") else "GET"
            n = normalize(action) or r.final_url
            self.add_endpoint(action, r.final_url, f"html:form({m})", depth, crawl=(m == "GET"))
            for inp in form["inputs"]:
                self.add_param(n, m, inp["name"], f"form on {r.final_url}", inp["type"],
                               user_controlled=inp["type"] not in ("hidden", "submit", "button"))
            if any(i["type"] == "password" for i in form["inputs"]):
                self.auth.append({"url": r.final_url, "evidence": "form with password field", "form_action": n})
        self.js_blobs_from(r.final_url, p.inline_js)
        for c in p.comments:
            if self.level >= 2 and re.search(r"(?i)todo|fixme|password|passwd|secret|api[_-]?key|credential|debug|internal", c):
                self.findings.add("info.comment", "HTML comment contains potentially sensitive keywords", "info", "low",
                                  r.final_url, c[:120], "Comment text matched a keyword; review manually. Not proof of a secret.",
                                  "Strip comments from production HTML.", "CWE-615", "A05:2021 Security Misconfiguration",
                                  key=r.final_url, method="keyword match (manual review)")

    def analyze_json(self, ep, r):
        try:
            data = json.loads(r.text)
        except ValueError:
            return
        if "api" not in ep.get("tags", []):
            self.api[ep["url"]] = {"url": ep["url"], "kind": "JSON endpoint", "source": ep["source"]}
        nodes = [data]
        seen = 0
        while nodes and seen < 2000:
            cur = nodes.pop()
            seen += 1
            if isinstance(cur, dict):
                for k, v in cur.items():
                    self.add_param(ep["url"], "GET", str(k)[:60], "JSON response key", "json_key", False)
                    nodes.append(v)
            elif isinstance(cur, list):
                nodes.extend(cur[:50])
            elif isinstance(cur, str) and (cur.startswith(("/", "http://", "https://"))) and len(cur) < 300:
                self.add_endpoint(cur, ep["url"], "json response", ep["depth"] + 1, base=ep["url"])

    def js_blobs_from(self, url, blobs):
        for b in blobs:
            self.analyze_js(url, b)

    def handle(self, ep, r):
        ep["status"], ep["content_type"], ep["timestamp"] = r.status, r.content_type, now()
        if r.error:
            ep["state"], ep["error"] = "FAILED", r.error
            self.errors.append({"resource": ep["url"], "error": r.error})
            return
        ep["state"] = "COMPLETED"
        if r.note:
            ep["note"] = r.note
        final = normalize(r.final_url)
        if final and final != ep["url"]:
            self.add_endpoint(final, ep["url"], "redirect", ep["depth"] + 1)
        self.analyze_http(r)
        if r.status >= 400 and r.status != 404:
            self.errors.append({"resource": ep["url"], "error": f"HTTP {r.status}"})
        ct = r.content_type
        if "html" in ct or not ct:
            self.analyze_body(ep, r)
            self.analyze_html(ep, r)
        elif "json" in ct:
            self.analyze_json(ep, r)
        elif "javascript" in ct:
            self.analyze_js(ep["url"], r.text)
        else:
            self.analyze_body(ep, r)

    # ---- crawler
    def crawl(self):
        fetched = 0
        while self.frontier and fetched < self.cfg.max_pages:
            batch = self.frontier[: self.cfg.max_pages - fetched]
            self.frontier = self.frontier[len(batch):]
            for ep in batch:
                ep["state"] = "SCANNING"
            with ThreadPoolExecutor(max_workers=self.cfg.concurrency) as ex:
                results = list(ex.map(lambda e: self.client.fetch(e["url"]), batch))
            for ep, r in zip(batch, results):
                fetched += 1
                try:
                    self.handle(ep, r)
                except Exception as e:  # analysis bugs must not stop the scan
                    ep["state"] = "FAILED"
                    self.errors.append({"resource": ep["url"], "error": f"analysis error: {type(e).__name__}: {e}"})
            if self.frontier:
                self.frontier.sort(key=lambda e: e["depth"])
        leftover = [e for e in self.endpoints.values() if e["state"] == "QUEUED"]
        if leftover:
            self.log(f"max-pages reached; {len(leftover)} queued URLs left unscanned")

    def robots_sitemap(self):
        r = self.client.fetch(urljoin(self.base, "/robots.txt"))
        sitemaps = []
        if not r.error and r.status == 200 and re.search(r"(?i)user-agent", r.text[:20000]):
            self.osint["robots_txt"] = True
            lines = r.text.splitlines()[:2000]
            self.robots = robotparser.RobotFileParser()
            self.robots.parse(lines)
            for ln in lines:
                k, _, v = ln.partition(":")
                k, v = k.strip().lower(), v.strip()
                if k == "sitemap" and v:
                    sitemaps.append(v)
                elif k == "disallow" and v.startswith("/") and "*" not in v:
                    self.add_endpoint(v, "robots.txt", "robots Disallow", 1, base=self.base, crawl=not self.cfg.respect_robots)
        else:
            self.osint["robots_txt"] = False
        for path in ("/.well-known/security.txt", "/security.txt"):
            s = self.client.fetch(urljoin(self.base, path))
            if not s.error and s.status == 200 and "contact:" in s.text.lower():
                self.osint["security_txt"] = path
                break
        else:
            self.osint["security_txt"] = None
        if not sitemaps:
            sitemaps = [urljoin(self.base, "/sitemap.xml")]
        urls_added, queue, done = 0, sitemaps[:5], 0
        while queue and done < 8 and urls_added < 500:
            sm = queue.pop(0)
            done += 1
            s = self.client.fetch(normalize(sm) or sm)
            if s.error or s.status != 200 or "<loc" not in s.text:
                continue
            self.osint["sitemap"] = True
            # regex on purpose: no XML parser, so no entity-expansion attacks
            for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", s.text[:2_000_000], re.S)[:500]:
                if loc.lower().endswith(".xml") and len(queue) < 5:
                    queue.append(loc)
                else:
                    self.add_endpoint(loc, "sitemap.xml", "sitemap", 1)
                    urls_added += 1

    # ---- probes
    def soft404_baseline(self):
        rnd = "".join(random.choices(string.ascii_lowercase, k=14))
        r = self.client.fetch(urljoin(self.base, f"/voidx-{rnd}.html"))
        if r.error:
            return None
        return {"status": r.status, "len": len(r.body), "hash": hashlib.sha1(r.body).hexdigest()}

    def looks_like_baseline(self, r):
        b = self.baseline
        if not b or r.status != b["status"]:
            return False
        return hashlib.sha1(r.body).hexdigest() == b["hash"] or abs(len(r.body) - b["len"]) <= max(32, b["len"] // 20)

    def probe_files(self):
        self.baseline = self.soft404_baseline()
        paths = [p for p in EXPOSED_FILES]
        with ThreadPoolExecutor(max_workers=self.cfg.concurrency) as ex:
            results = list(ex.map(lambda x: self.client.fetch(urljoin(self.base, x[0])), paths))
        for (path, check, title, sev, conf, cwe), r in zip(paths, results):
            if r.error or r.status != 200 or self.looks_like_baseline(r):
                continue
            try:
                ok = check(r)
            except Exception:
                ok = False
            if ok:
                url = urljoin(self.base, path)
                self.findings.add(f"exposed.{path}", title, sev, conf, url,
                                  f"HTTP 200, {len(r.body)} bytes, content matched expected structure of {path}",
                                  "The resource is publicly retrievable and its content was validated, not just its status code.",
                                  "Remove the file from the web root or deny access at the server.", cwe,
                                  "A05:2021 Security Misconfiguration", key=path, method="active probe + content validation")
        for path in AUTH_PATHS:
            r = self.client.fetch(urljoin(self.base, path))
            if r.error or self.looks_like_baseline(r):
                continue
            if r.status in (200, 401, 403) or (r.status in (301, 302) and r.chain):
                is_login = "password" in r.text.lower() or r.status in (401, 403)
                if is_login:
                    self.auth.append({"url": urljoin(self.base, path), "evidence": f"HTTP {r.status}" +
                                      (", password field" if "password" in r.text.lower() else "")})

    def methods(self):
        r = self.client.fetch(self.base, "OPTIONS")
        allow = r.headers.get("allow", "") if not r.error else ""
        if allow:
            self.osint["allowed_methods"] = allow
            risky = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT", "PATCH") if m in allow.upper()]
            if risky:
                self.findings.add("http.methods", "Potentially dangerous HTTP methods advertised", "low", "low", self.base,
                                  f"Allow: {allow}", "Advertised by OPTIONS only; not verified as functional.",
                                  "Disable unused methods.", "CWE-650", "A05:2021 Security Misconfiguration",
                                  method="OPTIONS (declared, unverified)")
        if self.base.startswith("https://"):
            plain = self.base.replace("https://", "http://", 1)
            p = self.client.fetch(plain)
            if not p.error and p.status < 400 and not p.final_url.startswith("https://") and not p.note:
                self.findings.add("tls.no-redirect", "HTTP does not redirect to HTTPS", "low", "high", plain,
                                  f"GET {plain} -> {p.status} (no redirect to https)", "Plain-HTTP site is served without upgrade.",
                                  "Redirect HTTP to HTTPS and enable HSTS.", "CWE-319", "A02:2021 Cryptographic Failures",
                                  method="HTTP request")

    # ---- deep: JS, API, CORS
    def analyze_js(self, url, text):
        text = text[:1_000_000]
        for m in re.finditer(r"""["'`](/(?:[A-Za-z0-9_\-.~%]+/?){1,8}(?:\?[^"'`\s]{0,100})?)["'`]""", text):
            path = m.group(1)
            if re.search(r"[A-Za-z]", path) and len(path) > 2 and not re.search(r"\.(?:png|jpe?g|gif|svg|woff2?|ttf|css)$", path):
                self.js_endpoints.setdefault(path, url)
        for m in re.finditer(r"""(?:https?|wss?)://[^\s"'`<>\\)]{4,200}""", text):
            self.js_endpoints.setdefault(m.group(0), url)
        for m in re.finditer(r"//[#@]\s*sourceMappingURL=(\S+)", text):
            self.osint.setdefault("source_maps", [])
            if len(self.osint["source_maps"]) < 50:
                self.osint["source_maps"].append({"js": url, "map": m.group(1)})
        for pat, label, sev, conf in SECRET_PATTERNS:
            m = re.search(pat, text)
            if m:
                self.js_findings.append({"type": label, "location": url, "sample": redact(m.group(0)), "confidence": conf})
                self.findings.add("secret." + label, f"Suspected secret in client-side code: {label}", sev, conf, url,
                                  f"matched pattern, value {redact(m.group(0))}",
                                  "Pattern/format match only; validity is not verified. Suspected secrets are reported separately from vulnerabilities.",
                                  "Rotate the credential if real and remove it from public assets.", "CWE-798",
                                  "A07:2021 Identification and Authentication Failures", key=f"{label}:{url}",
                                  method="regex format match (unverified)")
        for m in GENERIC_SECRET.finditer(text):
            val = m.group(2)
            if PLACEHOLDER.search(val) or len(set(val)) < 5:
                continue
            self.js_findings.append({"type": f"hardcoded {m.group(1)} assignment", "location": url,
                                     "sample": redact(val), "confidence": "low"})
            self.findings.add("secret.generic", "Possible hardcoded credential in client-side code", "low", "low", url,
                              f"{m.group(1)} = {redact(val)}", "Variable name suggests a credential; value may be a public identifier or placeholder.",
                              "Review manually; never ship private secrets to browsers.", "CWE-798",
                              "A07:2021 Identification and Authentication Failures", key=url, method="keyword + value heuristic")

    def js_analysis(self):
        scripts = [e for e in self.endpoints.values() if e["kind"] == "script" and e["state"] == "DISCOVERED"][:50]
        if not scripts:
            return
        with ThreadPoolExecutor(max_workers=self.cfg.concurrency) as ex:
            results = list(ex.map(lambda e: self.client.fetch(e["url"]), scripts))
        for ep, r in zip(scripts, results):
            ep["status"], ep["content_type"], ep["timestamp"] = r.status, r.content_type, now()
            if r.error or r.status != 200:
                ep["state"] = "FAILED"
                self.errors.append({"resource": ep["url"], "error": r.error or f"HTTP {r.status}"})
                continue
            ep["state"] = "COMPLETED"
            try:
                self.analyze_js(ep["url"], r.text)
            except Exception as e:
                self.errors.append({"resource": ep["url"], "error": f"JS analysis error: {type(e).__name__}"})
        for path, src in list(self.js_endpoints.items())[:400]:
            if path.startswith("/"):
                api_like = bool(re.search(r"(?i)/(api|rest|graphql|v\d+|rpc|oauth|auth|token)(/|$|\?)|\.json", path))
                ep = self.add_endpoint(path, src, "javascript string", 3, base=self.base, crawl=False)
                if ep and api_like:
                    self.api[ep["url"]] = {"url": ep["url"], "kind": "API-like route (from JavaScript)", "source": src}
            elif path.startswith(("ws://", "wss://")):
                self.osint.setdefault("websockets", []).append(path)

    def api_discovery(self):
        for path in API_DOC_PATHS:
            url = urljoin(self.base, path)
            r = self.client.fetch(url)
            if r.error or r.status != 200 or self.looks_like_baseline(r):
                continue
            try:
                d = json.loads(r.text)
            except ValueError:
                continue
            if isinstance(d, dict) and ("openapi" in d or "swagger" in d) and "paths" in d:
                self.api[url] = {"url": url, "kind": f"OpenAPI/Swagger {d.get('openapi') or d.get('swagger')}",
                                 "source": "common path", "operations": len(d["paths"])}
                for p_, ops in list(d["paths"].items())[:200]:
                    self.api[urljoin(self.base, p_)] = {"url": urljoin(self.base, p_), "kind": "documented operation",
                                                       "source": url, "methods": sorted(k.upper() for k in ops)[:8]
                                                       if isinstance(ops, dict) else []}
                self.findings.add("api.docs", "API documentation publicly accessible", "info", "confirmed", url,
                                  f"valid OpenAPI document with {len(d['paths'])} paths",
                                  "Informational: public docs expand the attack surface map; acceptable if intentional.",
                                  "Restrict if the API is not meant to be public.", "CWE-200",
                                  "A05:2021 Security Misconfiguration", method="content validation")
        for path in GRAPHQL_PATHS:
            url = urljoin(self.base, path)
            r = self.client.fetch(url + "?query=%7B__typename%7D")
            if r.error or self.looks_like_baseline(r):
                continue
            if r.status in (200, 400) and "json" in r.content_type and ('"__typename"' in r.text or "GraphQL" in r.text
                                                                      or "Must provide query" in r.text):
                self.api[url] = {"url": url, "kind": "GraphQL endpoint", "source": "common path"}
                q = self.client.fetch(url + "?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D")
                if not q.error and "queryType" in q.text and '"data"' in q.text:
                    self.findings.add("api.graphql-introspection", "GraphQL introspection enabled", "low", "confirmed", url,
                                      "introspection query returned schema data",
                                      "Schema disclosure aids attackers; acceptable on public APIs by design.",
                                      "Disable introspection in production.", "CWE-200", "A05:2021 Security Misconfiguration",
                                      method="read-only introspection query")

    def cors(self):
        targets = [self.base] + [u for u in list(self.api)[:4] if u.startswith("http")]
        for url in targets:
            for origin in ("https://voidx-cors-probe.invalid", "null"):
                r = self.client.fetch(url, headers={"Origin": origin})
                if r.error:
                    continue
                acao = r.headers.get("access-control-allow-origin", "")
                creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
                if acao == origin:
                    sev = "high" if creds else "low"
                    self.findings.add("cors.reflect", "CORS reflects arbitrary Origin" + (" with credentials" if creds else ""),
                                      sev, "confirmed", url, f"Origin: {origin} -> ACAO: {acao}, ACAC: {creds}",
                                      "Server echoed an untrusted origin" + ("; credentialed cross-site reads are possible." if creds
                                                                              else "; impact limited without credentials."),
                                      "Validate Origin against an allow-list; never combine reflection with credentials.",
                                      "CWE-942", "A05:2021 Security Misconfiguration", key=f"{origin}:{creds}",
                                      method="active probe (Origin header)")
                elif acao == "*" and url == self.base:
                    self.findings.add("cors.wildcard", "CORS allows any origin (wildcard)", "info", "high", url,
                                      "Access-Control-Allow-Origin: *", "Only a problem if the resource is non-public.",
                                      "Restrict to required origins for non-public resources.", "CWE-942",
                                      "A05:2021 Security Misconfiguration", method="active probe (Origin header)")

    # ---- lab-only active checks (non-destructive)
    def lab_checks(self):
        r = self.client.fetch(self.base, "TRACE")
        if not r.error and r.status == 200 and "TRACE" in r.text[:200]:
            self.findings.add("http.trace", "HTTP TRACE method enabled", "low", "confirmed", self.base,
                              "TRACE request echoed back", "Server reflects requests (cross-site tracing risk).",
                              "Disable TRACE.", "CWE-16", "A05:2021 Security Misconfiguration", method="lab active probe")
        tested = 0
        for (endpoint, method, name), prm in list(self.params.items()):
            if method != "GET" or prm["type"] in ("json_key", "hidden", "submit") or tested >= 25:
                continue
            tested += 1
            marker = "vx" + "".join(random.choices(string.ascii_lowercase, k=6))
            payload = f'{marker}"\'<{marker}>'
            p = urlparse(endpoint)
            q = [(k, payload if k == name else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
            if name not in dict(q):
                q.append((name, payload))
            url = urlunparse((p.scheme, p.netloc, p.path, "", urlencode(q), ""))
            r = self.client.fetch(url)
            if r.error or "html" not in r.content_type:
                continue
            if payload in r.text:
                self.findings.add("lab.reflection", "Input reflected without HTML encoding", "medium", "high", endpoint,
                                  f"parameter '{name}': marker with <, \" and ' returned verbatim in an HTML response",
                                  "Unencoded reflection in HTML is the precondition for reflected XSS; exploitability depends on context.",
                                  "Contextually encode output; add a restrictive CSP.", "CWE-79", "A03:2021 Injection",
                                  param=name, key=f"{p.path}:{name}", method="lab active probe (benign marker, no script)")
            elif marker in r.text:
                self.findings.add("lab.reflection-encoded", "Input reflected (encoded)", "info", "high", endpoint,
                                  f"parameter '{name}' reflected with metacharacters encoded", "Reflection exists but output is encoded.",
                                  "No action needed if encoding is consistent.", "CWE-79", "A03:2021 Injection",
                                  param=name, key=f"{p.path}:{name}", method="lab active probe")

    # ---- ports (real service identification, no static 'attack' table)
    def parse_ports(self):
        s = self.cfg.ports.strip().lower()
        if s in ("top", ""):
            return TOP_PORTS
        out = set()
        for part in s.split(","):
            part = part.strip()
            try:
                if "-" in part:
                    a, b = part.split("-", 1)
                    out.update(range(int(a), int(b) + 1))
                elif part:
                    out.add(int(part))
            except ValueError:
                self.log(f"ignoring invalid port spec '{part}'")
        return sorted(p for p in out if 0 < p < 65536)

    def probe_port(self, port):
        ip = self.ips[0]
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) != 0:
                s.close()
                return None
        except OSError:
            return None
        banner, service = b"", "unknown"
        try:
            s.settimeout(1.2)
            try:
                banner = s.recv(256)
            except socket.timeout:
                pass
            if not banner:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                    banner = s.recv(512)
                except (socket.timeout, OSError):
                    pass
            s.close()
            if not banner and port in (443, 8443, 993, 995, 465):
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=3) as raw, \
                        ctx.wrap_socket(raw, server_hostname=self.host) as ss:
                    ss.sendall(b"HEAD / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                    banner = ss.recv(512)
                    service = "tls+"
        except (OSError, ssl.SSLError):
            pass
        txt = banner.decode("latin-1", "replace").strip()
        first = txt.splitlines()[0][:120] if txt else ""
        if txt.startswith("SSH-"):
            service = "ssh"
        elif txt.startswith("HTTP/"):
            service = service.replace("unknown", "") + "http"
        elif re.match(r"220[ -].*FTP", txt, re.I):
            service = "ftp"
        elif re.match(r"220[ -].*SMTP", txt, re.I):
            service = "smtp"
        elif txt.startswith("+OK"):
            service = "pop3"
        elif txt.startswith("* OK"):
            service = "imap"
        elif "mysql" in txt.lower() or (len(banner) > 5 and banner[4:5] == b"\x0a" and re.search(rb"\d+\.\d+\.\d+", banner[5:20] or b"")):
            service = "mysql"
        elif service == "tls+":
            service = "tls"
        res = {"port": port, "state": "open", "service": service, "banner": first}
        if port == 6379:
            try:
                with socket.create_connection((ip, port), timeout=2) as rs:
                    rs.sendall(b"PING\r\n")
                    resp = rs.recv(64)
                    res["service"] = "redis" if resp.startswith((b"+PONG", b"-NOAUTH", b"-ERR")) else res["service"]
                    if resp.startswith(b"+PONG"):
                        res["unauthenticated"] = True
            except OSError:
                pass
        return res

    def port_scan(self):
        ports = self.parse_ports()
        self.log(f"port scan: {len(ports)} ports on {self.ips[0]} (workers={min(self.cfg.concurrency * 8, 64)})")
        with ThreadPoolExecutor(max_workers=min(self.cfg.concurrency * 8, 64)) as ex:
            self.ports_result = sorted([r for r in ex.map(self.probe_port, ports) if r], key=lambda r: r["port"])
        for r in self.ports_result:
            if r["service"] in ("mysql", "redis") or r.get("unauthenticated"):
                sev, conf = ("high", "confirmed") if r.get("unauthenticated") else ("low", "medium")
                self.findings.add(f"net.{r['service']}", f"{r['service']} service reachable from scan origin" +
                                  (" without authentication" if r.get("unauthenticated") else ""), sev, conf,
                                  f"{self.ips[0]}:{r['port']}", f"service fingerprint '{r['service']}', banner: {r['banner'][:80]!r}",
                                  "Database/cache service answered a protocol-level probe." +
                                  (" PING was answered without credentials." if r.get("unauthenticated") else ""),
                                  "Bind to localhost/private network or firewall the port; require authentication.",
                                  "CWE-306" if r.get("unauthenticated") else "CWE-668", "A05:2021 Security Misconfiguration",
                                  key=str(r["port"]), method="TCP connect + protocol probe")

    # ---- graph / report
    def build_graph(self):
        g = self.graph
        for ip in self.ips:
            g.append({"from": f"domain:{self.host}", "rel": "resolves_to", "to": f"ip:{ip}", "status": "observed (DNS)"})
        for sd in sorted(self.subdomains):
            g.append({"from": f"domain:{self.host}", "rel": "has_subdomain", "to": f"subdomain:{sd}",
                      "status": "observed (certificate SAN or link)"})
        for t in self.tech.values():
            g.append({"from": f"domain:{self.host}", "rel": "runs", "to": f"tech:{t['name']}" + (f" {t['version']}" if t["version"] else ""),
                      "status": "observed" if t["weight"] >= 1 else "inferred"})
        for f in self.findings.items.values():
            for a in f.affected[:3]:
                g.append({"from": f"endpoint:{a}", "rel": "has_finding", "to": f"finding:{f.id}", "status": "observed"})
        for e, src in list(self.emails.items())[:50]:
            g.append({"from": f"url:{src}", "rel": "mentions_email", "to": f"email:{e}", "status": "observed"})

    def tech_list(self):
        out = []
        for t in self.tech.values():
            conf = "high" if t["weight"] >= 2 else "medium" if t["weight"] >= 1 else "low"
            out.append({"name": t["name"], "version": t["version"], "confidence": conf, "evidence": t["evidence"][:5]})
        return sorted(out, key=lambda x: (-CONF_RANK[x["confidence"]], x["name"]))

    def report(self):
        fs = self.findings.sorted()
        vulns = [f for f in fs if f.severity != "info"]
        obs = [f for f in fs if f.severity == "info"]
        sev = Counter(f.severity for f in fs)
        states = Counter(e["state"].split(" ")[0] for e in self.endpoints.values())
        pages_ok = [e for e in self.endpoints.values() if e["state"] == "COMPLETED"]
        return {
            "tool": f"VOIDX {VERSION}",
            "executive_summary": {
                "target": self.cfg.target, "mode": self.cfg.mode,
                "findings_by_severity": dict(sev), "total_findings": len(vulns), "observations": len(obs),
                "endpoints_discovered": len(self.endpoints), "endpoints_scanned": len(pages_ok),
                "highest": [{"id": f.id, "title": f.title, "severity": f.severity, "confidence": f.confidence} for f in vulns[:5]]},
            "target": {"host": self.host, "base_url": self.base, "ips": self.ips},
            "scan_configuration": {k: v for k, v in asdict(self.cfg).items()},
            "discovered_assets": {"domains": [self.host], "subdomains": sorted(self.subdomains), "ips": self.ips,
                                  "external_hosts_referenced": sorted({urlparse(u).hostname for u in self.external if urlparse(u).hostname})[:100],
                                  "emails": [{"email": e, "found_on": u} for e, u in self.emails.items()]},
            "ip_information": {"reverse_dns": self.osint.get("reverse_dns"), "private_target": self.scope.target_private},
            "technologies": self.tech_list(),
            "endpoints": sorted(self.endpoints.values(), key=lambda e: (e["depth"], e["url"])),
            "parameters": list(self.params.values()),
            "http_analysis": self.http_samples,
            "tls": self.tls,
            "security_headers": {h: dict(c) for h, c in self.header_stats.items()},
            "cookies": list(self.cookies_seen.values()),
            "authentication_surface": self.auth,
            "api_discovery": list(self.api.values()),
            "javascript_discovery": {"endpoints": [{"value": k, "found_in": v} for k, v in list(self.js_endpoints.items())[:300]],
                                     "suspected_secrets": self.js_findings, "source_maps": self.osint.get("source_maps", []),
                                     "websockets": self.osint.get("websockets", [])},
            "osint_findings": {k: v for k, v in self.osint.items() if k not in ("source_maps", "websockets")},
            "ports": self.ports_result,
            "vulnerability_findings": [asdict(f) for f in vulns],
            "informational_observations": [asdict(f) for f in obs],
            "relationship_graph": self.graph,
            "scan_statistics": {"duration_s": round(time.time() - self.start, 1), "requests": self.client.stats["requests"],
                                "failed_requests": self.client.stats["failed_requests"], "retries": self.client.stats["retries"],
                                "bytes_received": self.client.stats["bytes"], "endpoint_states": dict(states)},
            "errors_unreachable": self.errors[:300],
            "timeline": self.timeline,
        }

    # ---- orchestration
    def run(self):
        self.log(f"VOIDX {VERSION} starting: target={self.cfg.target} mode={self.cfg.mode} "
                 f"depth={self.cfg.max_depth} pages={self.cfg.max_pages} conc={self.cfg.concurrency}")
        if not self.discover_target():
            return self.report()
        if self.level == 3 and not self.scope.target_private:
            sys.exit("LAB mode is restricted to loopback/private targets.")
        first = self.choose_base()
        if not first:
            self.log("target unreachable over HTTP/HTTPS")
        else:
            self.log(f"base URL: {self.base} (HTTP {first.status}, {first.http_version})")
            if self.base.startswith("https://"):
                self.tls = self.tls_probe(urlparse(self.base).port or 443)
                self.log(f"TLS: {self.tls.get('protocol', self.tls.get('error', 'n/a'))}")
            self.robots_sitemap()
            ep = self.add_endpoint(self.base, "scan target", "seed", 0)
            if ep:
                self.frontier = [e for e in self.frontier if e is not ep]
                ep["state"] = "SCANNING"
                self.handle(ep, first if first.final_url else self.client.fetch(self.base))
            self.log("crawling")
            self.crawl()
            if self.level >= 1:
                self.log("probing exposed files, auth surface, methods")
                self.probe_files()
                self.methods()
            if self.level >= 2:
                self.log("deep analysis: JavaScript, API discovery, CORS")
                self.js_analysis()
                self.api_discovery()
                self.cors()
            if self.level >= 3:
                self.log("lab checks (non-destructive)")
                self.lab_checks()
        if self.cfg.ports:
            self.port_scan()
        self.build_graph()
        self.log("scan complete")
        return self.report()


# --------------------------------------------------------------------------- output
def print_summary(rep):
    s = rep["executive_summary"]
    print("\n" + "=" * 62)
    print(f" VOIDX REPORT  target={s['target']}  mode={s['mode']}")
    print("=" * 62)
    print(f" Endpoints discovered: {s['endpoints_discovered']}   scanned: {s['endpoints_scanned']}")
    print(f" Findings: {s['findings_by_severity'] or 'none'}   observations: {s['observations']}")
    if rep["technologies"]:
        print(" Technologies: " + ", ".join(f"{t['name']}{' ' + t['version'] if t['version'] else ''} ({t['confidence']})"
                                            for t in rep["technologies"][:8]))
    if rep["ports"]:
        print(" Open ports:   " + ", ".join(f"{p['port']}/{p['service']}" for p in rep["ports"]))
    print("-" * 62)
    for f in rep["vulnerability_findings"]:
        print(f" [{f['severity'].upper():8}|{f['confidence']:9}] {f['id']}  {f['title']}")
        print(f"      affected: {f['affected'][0]}" + (f"  (+{f['occurrences'] - 1} more)" if f["occurrences"] > 1 else ""))
        print(f"      evidence: {f['evidence'][0][:110] if f['evidence'] else '-'}")
    if not rep["vulnerability_findings"]:
        print(" No findings above informational level.")
    print("-" * 62)
    st = rep["scan_statistics"]
    print(f" {st['requests']} requests, {st['failed_requests']} failed, {st['duration_s']}s, errors logged: {len(rep['errors_unreachable'])}")


def write_markdown(rep, path):
    L = [f"# VOIDX Scan Report - {rep['target']['host']}", "", "## Executive summary",
         f"- Mode: `{rep['executive_summary']['mode']}`",
         f"- Findings by severity: {rep['executive_summary']['findings_by_severity']}",
         f"- Endpoints discovered/scanned: {rep['executive_summary']['endpoints_discovered']}/{rep['executive_summary']['endpoints_scanned']}", "",
         "## Technologies"]
    L += [f"- {t['name']} {t['version'] or ''} - {t['confidence']} confidence" for t in rep["technologies"]] or ["- none detected"]
    L += ["", "## Findings"]
    for f in rep["vulnerability_findings"]:
        L += [f"### {f['id']} - {f['title']}", f"- Severity: **{f['severity']}**, confidence: **{f['confidence']}**, method: {f['detection']}",
              f"- CWE: {f['cwe'] or 'n/a'}  |  OWASP: {f['owasp'] or 'n/a'}",
              f"- Affected ({f['occurrences']}): " + ", ".join(f"`{a}`" for a in f["affected"][:5]),
              f"- Evidence: " + "; ".join(f["evidence"][:3]), f"- Why: {f['reason']}", f"- Fix: {f['remediation']}", ""]
    L += ["## Informational observations"] + [f"- {f['title']} ({f['affected'][0] if f['affected'] else ''})"
                                              for f in rep["informational_observations"]]
    L += ["", "## Errors / unreachable"] + [f"- {e['resource']}: {e['error']}" for e in rep["errors_unreachable"][:50]]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------- UI
class Style:
    """ANSI styling that degrades gracefully (no TTY / NO_COLOR / dumb terminal)."""
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"

    @staticmethod
    def enable_windows():
        if os.name == "nt":
            os.system("")      # switches on ANSI escape processing in modern Windows consoles

    @classmethod
    def c(cls, text, code):
        return f"\033[{code}m{text}\033[0m" if cls.on else text

    @classmethod
    def fg(cls, text, n):
        return cls.c(text, f"38;5;{n}")


def _unicode_ok():
    try:
        "█╗╭─│❯".encode(sys.stdout.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


LOGO = [
    "██╗   ██╗ ██████╗ ██╗██████╗ ██╗  ██╗",
    "██║   ██║██╔═══██╗██║██╔══██╗╚██╗██╔╝",
    "██║   ██║██║   ██║██║██║  ██║ ╚███╔╝ ",
    "╚██╗ ██╔╝██║   ██║██║██║  ██║ ██╔██╗ ",
    " ╚████╔╝ ╚██████╔╝██║██████╔╝██╔╝ ██╗",
    "  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝",
]
ART = [
    "              ▄▄▄▄▄▄▄▄▄▄▄▄▄▄              ",
    "          ▄▄██▀▀▀▀▀▀▀▀▀▀▀▀▀▀██▄▄          ",
    "        ▄██▀                  ▀██▄        ",
    "       ██▀                      ▀██       ",
    "      ██▌   ▄████▄      ▄████▄   ▐██      ",
    "      ██    ██████      ██████    ██      ",
    "      ██▌   ▀████▀  ▄▄  ▀████▀   ▐██      ",
    "       ██▄         ▀██▀         ▄██       ",
    "        ▀██▄        ▀▀        ▄██▀        ",
    "          ▀██▄▄            ▄▄██▀          ",
    "            ▀▀██  ▐▌▐▌▐▌▐▌  ██▀▀          ",
    "              ▀▀██▄▄▄▄▄▄▄▄██▀▀            ",
    "                 ▀▀▀▀▀▀▀▀                 ",
]
ART_COLORS = [54, 55, 92, 93, 99, 99, 105, 105, 111, 111, 117, 123, 159]

LOGO_ASCII = r"""
 __   _____ ___ ___ __  __
 \ \ / / _ \_ _|   \\ \/ /
  \ V / (_) | || |) |>  <
   \_/ \___/___|___//_/\_\
"""
GRADIENT = [93, 99, 105, 111, 117, 123]   # violet -> cyan


def banner():
    S = Style
    S.enable_windows()
    if S.on:                                   # start from a clean screen so the logo sits at the very top
        print("\033[2J\033[H", end="")
    if not _unicode_ok():
        print(S.fg(LOGO_ASCII, 105))
        print(f" OSINT & Web Security Scanner v{VERSION}")
        print(" Authorized targets only. Evidence-based results, no guesswork.\n")
        return
    print()
    for i, line in enumerate(ART):
        print("  " + S.fg(line, ART_COLORS[i % len(ART_COLORS)]))
    print()
    for i, line in enumerate(LOGO):
        print("    " + S.fg(line, GRADIENT[i % len(GRADIENT)]))
    print()
    print("    " + S.fg("▀▄" * 19, 60))
    print("    " + S.c("OSINT & Web Security Scanner", "1;97") + S.fg(f"  ·  v{VERSION}", 111))
    print("    " + S.fg("Authorized targets only. Evidence-based results, no guesswork.", 245))
    print()


MENU_MODES = [
    ("1", "quick",  "DNS, TLS, headers, tech fingerprint",     46),
    ("2", "normal", "+ crawl, forms, cookies, exposed files",   117),
    ("3", "deep",   "+ JS analysis, API discovery, CORS",       214),
    ("4", "lab",    "+ active checks (local/private only)",     203),
]


def _box(rows, width=58):
    """rows: list of (plain_text, colored_text) or None for a divider."""
    S = Style
    u = _unicode_ok()
    tl, tr, bl, br, h, v, lj, rj = ("╭", "╮", "╰", "╯", "─", "│", "├", "┤") if u else ("+", "+", "+", "+", "-", "|", "+", "+")
    edge = lambda s: S.fg(s, 99)
    out = [edge(tl + h * (width + 2) + tr)]
    for r in rows:
        if r is None:
            out.append(edge(lj + h * (width + 2) + rj))
        else:
            plain, colored = r
            out.append(edge(v) + " " + colored + " " * max(0, width - len(plain)) + " " + edge(v))
    out.append(edge(bl + h * (width + 2) + br))
    return "\n".join("  " + o for o in out)


def _ask(label, default=""):
    S = Style
    arrow = "❯" if _unicode_ok() else ">"
    hint = S.fg(f" ({default})", 244) if default else ""
    return input(f"  {S.fg(arrow, 123)} {S.c(label, '1;97')}{hint} ").strip()


def interactive():
    S = Style
    title = "SELECT SCAN MODE"
    rows = [(title, S.c(title, "1;97")), None]
    for key, name, desc, col in MENU_MODES:
        plain = f"[{key}]  {name:<7} {desc}"
        colored = S.fg(f"[{key}]", col) + "  " + S.c(f"{name:<7}", "1;97") + " " + S.fg(desc, 250)
        rows.append((plain, colored))
    rows.append(None)
    foot = "Enter = normal   ·   Ctrl+C = quit"
    rows.append((foot, S.fg(foot, 244)))
    print(_box(rows))
    print()

    target = ""
    while not target:
        target = _ask("Target (URL, domain or IP):")
    names = {k: n for k, n, _, _ in MENU_MODES}
    while True:
        choice = _ask("Mode [1-4 or name]:", "normal").lower() or "normal"
        mode = names.get(choice, choice)
        if mode in MODES:
            break
        print("  " + S.fg("✗ pick 1-4 or quick/normal/deep/lab", 203))
    ports = _ask("Ports (blank = none, 'top', or e.g. 1-1024,8080):")
    print()
    print("  " + S.fg("▶ launching ", 46) + S.c(f"{mode}", "1;97") + S.fg(f" scan on {target}", 245) + "\n")
    return target, mode, ports


def main():
    banner()                                   # shown first, every time the tool is opened
    ap = argparse.ArgumentParser(description="VOIDX evidence-based OSINT & web security scanner")
    ap.add_argument("target", nargs="?")
    ap.add_argument("-m", "--mode", choices=MODES, default=None)
    ap.add_argument("--depth", type=int)
    ap.add_argument("--max-pages", type=int)
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--delay", type=float, default=0.2, help="per-host delay (s)")
    ap.add_argument("--max-rps", type=float, default=20.0, help="global requests/second")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--allow-subdomains", action="store_true")
    ap.add_argument("--allow-domain", action="append", default=[])
    ap.add_argument("--no-robots", action="store_true", help="do not honour robots.txt while crawling")
    ap.add_argument("--ports", default="", help="'top' or list/range, e.g. 22,80,443 or 1-1024")
    ap.add_argument("--user-agent")
    ap.add_argument("--authorized", action="store_true", help="confirm you are authorized to test a public target")
    ap.add_argument("--out", help="write JSON report")
    ap.add_argument("--md", help="write Markdown report")
    a = ap.parse_args()
    interactive_run = not a.target
    if interactive_run:
        a.target, mode, a.ports = interactive()
        a.mode = a.mode or mode
    a.mode = a.mode or "normal"
    if a.mode not in MODES:
        sys.exit("mode must be quick, normal, deep or lab")
    if not a.target:
        sys.exit("no target given")
    d, p = MODE_LIMITS[a.mode]
    cfg = Config(target=a.target, mode=a.mode, max_depth=a.depth if a.depth is not None else d,
                 max_pages=a.max_pages or p, timeout=a.timeout, delay=a.delay, max_rps=max(0.1, a.max_rps),
                 concurrency=max(1, min(a.concurrency, 20)), allow_subdomains=a.allow_subdomains,
                 extra_domains=a.allow_domain, respect_robots=not a.no_robots, ports=a.ports,
                 authorized=a.authorized, user_agent=a.user_agent or Config.user_agent)
    host = urlparse(cfg.target if "//" in cfg.target else "//" + cfg.target).hostname
    if not host:
        sys.exit("invalid target")
    ips = resolve(host)
    if ips and not all(is_private_ip(i) for i in ips) and not cfg.authorized:
        if interactive_run:
            ans = input(f"{host} is a public target. Type YES if you own it or have written permission to test it: ")
            if ans.strip() != "YES":
                sys.exit("Aborted: no authorization confirmed.")
        else:
            sys.exit(f"{host} is a public target. Re-run with --authorized to confirm you have permission to test it.")
    try:
        sc = Scanner(cfg)
        rep = sc.run()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
    print_summary(rep)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2, default=str)
        print(f" JSON report: {a.out}")
    if a.md:
        write_markdown(rep, a.md)
        print(f" Markdown report: {a.md}")


if __name__ == "__main__":
    main()
