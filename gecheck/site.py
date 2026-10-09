"""gecheck site: checks a published website.

GET requests only, about 30 of them with a pause between them.
"""

import hashlib
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .i18n import SITE_TEXTS, tri
from .model import SEV_RANK, Finding
from .scanner import Options, ScanResult

UA = f"GoldenEye-Check-Site/{__version__} (+https://goldeneye.kz)"
TIMEOUT = 10
PAUSE = 0.2
MAX_BODY = 65536


@dataclass
class Response:
    url: str
    status: int
    headers: object
    body: bytes
    error: str = ""

    def header(self, name):
        return self.headers.get(name) if self.headers is not None else None

    def header_all(self, name):
        if self.headers is None:
            return []
        return self.headers.get_all(name) or []


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, follow=True) -> Response:
    handlers = [] if follow else [_NoRedirect]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return Response(resp.geturl(), resp.status, resp.headers, resp.read(MAX_BODY))
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY)
        except Exception:
            body = b""
        return Response(url, e.code, e.headers, body)
    except Exception as e:  # network, DNS, TLS
        return Response(url, 0, None, b"", error=str(e)[:200])
    finally:
        time.sleep(PAUSE)


def _f(key, severity, category, where, anchor=None, detail=None, **kw):
    t = SITE_TEXTS[key]
    return Finding(rule=f"ge.site.{key.replace('_', '-')}", engine="site", severity=severity,
                   category=category, file=where, line=None, title=tri(t["title"], **kw),
                   fix=tri(t["fix"], **kw), cwe=t.get("cwe"), anchor=anchor or key,
                   detail=tri(t["detail"], **kw) if detail and "detail" in t else {})


# HTTPS and certificate

def check_tls(host, port=443):
    out = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as e:
        return [_f("cert_invalid", "critical", "config", f"https://{host}", detail=True, reason=str(e.verify_message or e)[:120])]
    except (OSError, ssl.SSLError):
        return [_f("no_https", "critical", "config", f"https://{host}")]
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (not_after - datetime.now(timezone.utc)).days
    if days < 14:
        out.append(_f("cert_expiring", "high", "config", f"https://{host}", detail=True, days=days))
    elif days < 30:
        out.append(_f("cert_expiring", "medium", "config", f"https://{host}", detail=True, days=days))
    if version in ("TLSv1", "TLSv1.1"):
        out.append(_f("old_tls", "medium", "config", f"https://{host}", detail=True, version=version))
    return out


def check_redirect(host):
    r = fetch(f"http://{host}/", follow=False)
    if r.status == 0:
        return []  # port 80 is closed
    location = r.header("Location") or ""
    if r.status in (301, 302, 307, 308) and location.lower().startswith("https://"):
        return []
    return [_f("no_redirect", "medium", "config", f"http://{host}/")]


# Headers and cookies

SESSION_COOKIE = re.compile(r"(sess|sid|auth|token|login|jwt|remember)", re.I)
VERSION_RE = re.compile(r"\d+\.\d+")


def check_headers(r: Response):
    out, where = [], r.url
    h = {k.lower(): v for k, v in (r.headers.items() if r.headers is not None else [])}
    hsts = h.get("strict-transport-security", "")
    if r.url.startswith("https://"):
        if not hsts:
            out.append(_f("hsts_missing", "medium", "config", where))
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15552000:
                out.append(_f("hsts_short", "low", "config", where, detail=True, seconds=m.group(1)))
    csp = h.get("content-security-policy", "")
    if not csp:
        out.append(_f("csp_missing", "medium", "config", where))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(_f("nosniff_missing", "low", "config", where))
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        out.append(_f("clickjacking", "low", "config", where))
    if "referrer-policy" not in h:
        out.append(_f("referrer_missing", "low", "config", where))
    for name in ("server", "x-powered-by"):
        value = h.get(name, "")
        if VERSION_RE.search(value):
            out.append(_f("server_version", "low", "config", where, anchor=name, detail=True,
                          header=name, value=value[:60]))
    for raw in r.header_all("Set-Cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        missing = [flag for flag, present in (("Secure", "secure" in attrs), ("HttpOnly", "httponly" in attrs),
                                              ("SameSite", "samesite" in attrs)) if not present]
        if missing:
            sev = "medium" if SESSION_COOKIE.search(name) and ("Secure" in missing or "HttpOnly" in missing) else "low"
            out.append(_f("cookie_flags", sev, "config", where, anchor=name, detail=True,
                          name=name, flags=", ".join(missing)))
    return out


# Exposed service files

def _env(b):
    return bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=\S", b))


EXPOSED = [
    # path, severity, content check (filters out soft 404 and SPA)
    (".env", "critical", _env),
    (".env.local", "critical", _env),
    (".env.production", "critical", _env),
    (".git/HEAD", "critical", lambda b: b.startswith(b"ref: ") or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None),
    (".git/config", "critical", lambda b: b"[core]" in b),
    (".svn/entries", "high", lambda b: b.strip()[:2].isdigit() or b"<wc-entries" in b),
    (".htpasswd", "critical", lambda b: re.search(rb"(?m)^[\w.-]+:\$", b) is not None),
    ("backup.sql", "critical", lambda b: re.search(rb"(?i)(create table|insert into)", b) is not None),
    ("dump.sql", "critical", lambda b: re.search(rb"(?i)(create table|insert into)", b) is not None),
    ("database.sql", "critical", lambda b: re.search(rb"(?i)(create table|insert into)", b) is not None),
    ("db.sql", "critical", lambda b: re.search(rb"(?i)(create table|insert into)", b) is not None),
    ("backup.zip", "high", lambda b: b.startswith(b"PK\x03\x04")),
    ("site.zip", "high", lambda b: b.startswith(b"PK\x03\x04")),
    ("wp-config.php.bak", "critical", lambda b: b"DB_PASSWORD" in b),
    ("config.php.bak", "critical", lambda b: b"<?php" in b),
    (".vscode/sftp.json", "critical", lambda b: b'"host"' in b and (b'"password"' in b or b'"privateKeyPath"' in b)),
    (".DS_Store", "low", lambda b: b[4:8] == b"Bud1"),
    ("phpinfo.php", "high", lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("info.php", "high", lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("server-status", "medium", lambda b: b"Apache Server Status" in b),
    ("docker-compose.yml", "medium", lambda b: b"services:" in b),
]

LISTING_DIRS = ["uploads/", "images/", "img/", "assets/", "files/", "backup/", "backups/", "static/"]


def _fingerprint(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def check_exposed(base: str):
    out = []
    # soft 404: some sites return 200 for any path, so compare with the response for a missing file
    probe = fetch(f"{base}/gecheck-{int(time.time())}-does-not-exist.txt")
    soft404 = _fingerprint(probe.body) if probe.status == 200 else None
    for path, sev, looks_real in EXPOSED:
        r = fetch(f"{base}/{path}")
        if r.status != 200 or not r.body.strip():
            continue
        if soft404 and _fingerprint(r.body) == soft404:
            continue
        if not looks_real(r.body):
            continue
        out.append(_f("exposed_file", sev, "secrets" if sev == "critical" else "config", f"{base}/{path}",
                      anchor=path, path=path))
    for d in LISTING_DIRS:
        r = fetch(f"{base}/{d}")
        # Apache/nginx: "Index of /", http.server and some panels: "Directory listing for /"
        if r.status == 200 and re.search(rb"<title>\s*(Index of|Directory listing for) /", r.body, re.I):
            out.append(_f("dir_listing", "medium", "config", f"{base}/{d}", anchor=d, path=d))
    return out


# Entry point

def normalize(url: str):
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"This does not look like a site address: {url}")
    base = urlunsplit((parts.scheme, parts.netloc, "", "", "")).rstrip("/")
    return base, parts.hostname, parts.scheme


def run_site(url: str, log=print) -> ScanResult:
    base, host, scheme = normalize(url)
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    findings, warnings = [], []

    log("  HTTPS and certificate...")
    if scheme == "https":
        findings += check_tls(host, urlsplit(base).port or 443)
        if urlsplit(base).port is None:
            findings += check_redirect(host)
    else:
        warnings.append("The check was started with http://, so HTTPS and the certificate were not checked")

    log("  headers and cookies...")
    main = fetch(base + "/")
    if main.status == 0:
        warnings.append(f"The site did not open: {main.error}")
    else:
        findings += check_headers(main)
        log("  exposed files...")
        findings += check_exposed(base)

    findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.file))
    return ScanResult(root=Path(host), findings=findings, warnings=warnings,
                      engines={"site": {"version": __version__, "status": "ok", "findings": len(findings)}},
                      started_at=started.isoformat(timespec="seconds"),
                      duration=round(time.monotonic() - t0, 1), options=Options(deps=False, history=False),
                      kind="site")
