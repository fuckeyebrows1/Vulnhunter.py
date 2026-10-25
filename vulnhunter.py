#!/usr/bin/env python3
"""Vulnhunter - an authorized, read-only web application vulnerability scanner.

Vulnhunter runs a small, non-destructive set of checks against a single web
target that you own or are explicitly authorized to test:

  * HTTP security headers (HSTS, CSP, clickjacking, MIME sniffing, referrer)
  * Cookie flags (Secure, HttpOnly, SameSite)
  * CORS policy misconfiguration
  * TLS version, cipher strength, certificate validity and expiry
  * Transport encryption (plaintext HTTP availability / missing redirect)
  * A short list of commonly exposed files and debug endpoints
  * Allowed HTTP methods (including TRACE)
  * Information disclosure (version banners, directory listing, stack traces,
    interesting robots.txt entries)

Only the Python standard library is required (3.8+).

Reports are printed to the terminal and can be written as JSON and/or a
self-contained HTML file.

Legal: scanning systems without permission is illegal in most jurisdictions.
Vulnhunter refuses to scan public hosts unless you pass --authorized, which is
your statement that you have permission.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import html
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "1.0.0"

DEFAULT_USER_AGENT = "Vulnhunter/%s (+authorized security testing)" % VERSION

SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

COLORS = {
    "critical": "\033[1;95m",
    "high": "\033[1;91m",
    "medium": "\033[1;93m",
    "low": "\033[1;96m",
    "info": "\033[1;94m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


class AuthorizationError(RuntimeError):
    """Raised when a scan would touch a host without explicit authorization."""


class UsageError(RuntimeError):
    """Raised for invalid CLI input."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class Finding:
    check: str
    title: str
    severity: str
    description: str
    evidence: str = ""
    remediation: str = ""
    references: List[str] = dataclasses.field(default_factory=list)
    url: str = ""

    def sort_key(self) -> Tuple[int, str, str]:
        return (-SEVERITY_RANK.get(self.severity, 0), self.check, self.title)

    def to_dict(self) -> Dict[str, object]:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
            "url": self.url,
        }


@dataclasses.dataclass
class HttpResult:
    url: str
    method: str = "GET"
    status: Optional[int] = None
    headers: List[Tuple[str, str]] = dataclasses.field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None

    def header(self, name: str, default: str = "") -> str:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return default

    def header_all(self, name: str) -> List[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def text(self, limit: Optional[int] = None) -> str:
        data = self.body if limit is None else self.body[:limit]
        return data.decode("latin-1", errors="replace")


@dataclasses.dataclass
class ScanOptions:
    checks: List[str] = dataclasses.field(default_factory=list)
    timeout: float = 8.0
    delay: float = 0.0
    verify_tls: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    max_paths: int = 12
    authorized: bool = False


@dataclasses.dataclass
class ScanReport:
    target: str
    final_url: str
    status: Optional[int]
    redirects: int
    findings: List[Finding]
    errors: List[str]
    checks_run: List[str]
    started_at: str
    duration: float

    @property
    def summary(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": "vulnhunter",
            "version": VERSION,
            "target": self.target,
            "final_url": self.final_url,
            "status": self.status,
            "redirects": self.redirects,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration, 3),
            "summary": self.summary,
            "checks_run": list(self.checks_run),
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return redirects to the caller instead of following them."""

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


class HttpClient:
    def __init__(
        self,
        timeout: float = 8.0,
        user_agent: str = DEFAULT_USER_AGENT,
        verify: bool = True,
        delay: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify = verify
        self.delay = delay
        context = ssl.create_default_context() if verify else ssl._create_unverified_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        max_bytes: int = 131072,
    ) -> HttpResult:
        if self.delay:
            time.sleep(self.delay)
        base_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if headers:
            base_headers.update(headers)
        req = urllib.request.Request(url, method=method, headers=base_headers)
        start = time.perf_counter()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = b"" if method == "HEAD" else resp.read(max_bytes)
                status = int(resp.status)
                lines = list(resp.headers.items())
        except urllib.error.HTTPError as exc:  # includes unfollowed 3xx
            try:
                body = b"" if method == "HEAD" else exc.read(max_bytes)
            except Exception:  # pragma: no cover - defensive
                body = b""
            status = int(exc.code)
            lines = list(exc.headers.items()) if exc.headers else []
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError, ValueError) as exc:
            return HttpResult(
                url=url,
                method=method,
                elapsed=time.perf_counter() - start,
                error=str(getattr(exc, "reason", exc)),
            )
        return HttpResult(
            url=url,
            method=method,
            status=status,
            headers=lines,
            body=body,
            elapsed=time.perf_counter() - start,
        )


def fetch_chain(client: HttpClient, url: str, max_redirects: int = 8) -> List[HttpResult]:
    """Request ``url`` and follow redirects manually, returning every hop."""
    chain: List[HttpResult] = []
    current = url
    seen = set()
    for _ in range(max_redirects + 1):
        if current in seen:
            break
        seen.add(current)
        result = client.request(current)
        chain.append(result)
        location = result.header("location")
        if result.status in (301, 302, 303, 307, 308) and location:
            current = urllib.parse.urljoin(current, location)
            continue
        break
    return chain


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise UsageError("target must not be empty")
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise UsageError("only http:// and https:// targets are supported")
    if not parsed.hostname:
        raise UsageError("target does not contain a hostname")
    if not parsed.path:
        parsed = parsed._replace(path="/")
    return urllib.parse.urlunparse(parsed)


def is_local_target(host: str) -> bool:
    """True for loopback, private, link-local and local-only hostnames."""
    host = host.strip("[]").strip().lower()
    if host in ("localhost", "localhost.localdomain", "::1"):
        return True
    if host.endswith((".local", ".localhost", ".internal", ".test")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def clip(value: str, limit: int = 240) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _first_lines(text: str, limit: int = 3, width: int = 200) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(clip(line, width) for line in lines[:limit])


def _csp_directives(value: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


# --------------------------------------------------------------------------- #
# Scan context and check registry
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class ScanContext:
    url: str
    parsed: urllib.parse.ParseResult
    client: HttpClient
    chain: List[HttpResult]
    home: HttpResult
    max_paths: int
    errors: List[str]

    @property
    def origin(self) -> str:
        parsed = self.parsed
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, "", "", "", "")
        ).rstrip("/")

    def path_url(self, path: str) -> str:
        return self.origin + path


@dataclasses.dataclass
class Check:
    id: str
    name: str
    func: Callable[[ScanContext], List[Finding]]


# --------------------------------------------------------------------------- #
# Checks: HTTP security headers
# --------------------------------------------------------------------------- #


def check_headers(ctx: ScanContext) -> List[Finding]:
    home = ctx.home
    if not home.ok:
        return []
    findings: List[Finding] = []
    url = home.url
    https = urllib.parse.urlparse(url).scheme == "https"

    hsts = home.header("strict-transport-security").strip()
    if https:
        if not hsts:
            findings.append(
                Finding(
                    check="headers",
                    title="Strict-Transport-Security header missing",
                    severity="medium",
                    description=(
                        "The site is served over HTTPS but does not send HSTS, so browsers "
                        "will happily downgrade to plaintext HTTP on the first visit."
                    ),
                    evidence="Strict-Transport-Security: <not set>",
                    remediation=(
                        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains "
                        "(add preload once you are ready)."
                    ),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                    url=url,
                )
            )
        else:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            max_age = int(match.group(1)) if match else 0
            if max_age < 15552000:
                findings.append(
                    Finding(
                        check="headers",
                        title="HSTS max-age too short",
                        severity="low",
                        description=(
                            "The HSTS lifetime is below the recommended six months, which "
                            "leaves room for downgrade attacks between visits."
                        ),
                        evidence="Strict-Transport-Security: %s" % clip(hsts),
                        remediation="Use max-age=31536000 (one year) or more.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                        url=url,
                    )
                )

    csp = home.header("content-security-policy").strip()
    if not csp:
        findings.append(
            Finding(
                check="headers",
                title="Content-Security-Policy header missing",
                severity="medium",
                description=(
                    "Without a CSP the browser will execute any script an attacker manages "
                    "to inject, which turns most HTML injection bugs into full XSS."
                ),
                evidence="Content-Security-Policy: <not set>",
                remediation=(
                    "Start with a report-only policy (Content-Security-Policy-Report-Only) "
                    "and tighten it to a nonce or hash based script-src."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                url=url,
            )
        )
    else:
        directives = _csp_directives(csp)
        script_sources = directives.get("script-src") or directives.get("default-src") or []
        weak_tokens = [t for t in script_sources if t in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:")]
        if weak_tokens:
            findings.append(
                Finding(
                    check="headers",
                    title="Content-Security-Policy allows unsafe script sources",
                    severity="low",
                    description=(
                        "The script policy permits tokens that defeat much of the protection "
                        "a CSP is meant to provide."
                    ),
                    evidence="script-src: %s" % clip(" ".join(script_sources)),
                    remediation=(
                        "Remove 'unsafe-inline', 'unsafe-eval', wildcards and data: from "
                        "script-src; use nonces or hashes instead."
                    ),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                    url=url,
                )
            )

    has_frame_ancestors = "frame-ancestors" in _csp_directives(csp)
    xfo = home.header("x-frame-options").strip().lower()
    if not has_frame_ancestors and not xfo:
        findings.append(
            Finding(
                check="headers",
                title="Clickjacking protection missing",
                severity="medium",
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can "
                    "be framed by any site and used for clickjacking."
                ),
                evidence="X-Frame-Options: <not set>; frame-ancestors: <not set>",
                remediation="Send X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'self'.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
                url=url,
            )
        )

    nosniff = home.header("x-content-type-options").strip().lower()
    if nosniff != "nosniff":
        findings.append(
            Finding(
                check="headers",
                title="X-Content-Type-Options missing or invalid",
                severity="low",
                description=(
                    "Without 'nosniff' browsers may guess content types, which can turn an "
                    "uploaded file into executable script."
                ),
                evidence="X-Content-Type-Options: %s" % (clip(nosniff) or "<not set>"),
                remediation="Send X-Content-Type-Options: nosniff on every response.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                url=url,
            )
        )

    referrer = home.header("referrer-policy").strip().lower()
    if not referrer:
        findings.append(
            Finding(
                check="headers",
                title="Referrer-Policy header missing",
                severity="low",
                description=(
                    "URLs (which may contain tokens or identifiers) leak to third parties in "
                    "the Referer header."
                ),
                evidence="Referrer-Policy: <not set>",
                remediation="Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                url=url,
            )
        )
    elif referrer in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append(
            Finding(
                check="headers",
                title="Permissive Referrer-Policy",
                severity="low",
                description="This policy sends full URLs to third parties on cross-origin requests.",
                evidence="Referrer-Policy: %s" % referrer,
                remediation="Use strict-origin-when-cross-origin or no-referrer.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                url=url,
            )
        )

    if not home.header("permissions-policy").strip():
        findings.append(
            Finding(
                check="headers",
                title="Permissions-Policy header missing",
                severity="info",
                description=(
                    "Browser features such as camera, microphone and geolocation are not "
                    "restricted for this origin and its frames."
                ),
                evidence="Permissions-Policy: <not set>",
                remediation="Disable features you do not use, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=().",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                url=url,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# Checks: cookies
# --------------------------------------------------------------------------- #


def check_cookies(ctx: ScanContext) -> List[Finding]:
    home = ctx.home
    if not home.ok:
        return []
    raw_cookies = home.header_all("set-cookie")
    if not raw_cookies:
        return []
    https = urllib.parse.urlparse(home.url).scheme == "https"
    findings: List[Finding] = []
    seen: set = set()

    for raw in raw_cookies:
        parts = raw.split(";")
        name = parts[0].split("=", 1)[0].strip() or "<unnamed>"
        attributes = [p.strip().lower() for p in parts[1:]]
        attr_names = {a.split("=", 1)[0] for a in attributes}
        if name in seen:
            continue
        seen.add(name)

        missing = []
        if https and "secure" not in attr_names:
            missing.append("Secure")
        if "httponly" not in attr_names:
            missing.append("HttpOnly")
        if "samesite" not in attr_names:
            missing.append("SameSite")
        if missing:
            findings.append(
                Finding(
                    check="cookies",
                    title="Cookie '%s' is missing security attributes" % name,
                    severity="medium" if "HttpOnly" in missing and "Secure" in missing else "low",
                    description=(
                        "The cookie is set without %s, so it can be read by injected "
                        "JavaScript, sent over plaintext HTTP, or attached on cross-site "
                        "requests." % ", ".join(missing)
                    ),
                    evidence=clip(raw),
                    remediation=(
                        "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict) and a "
                        "narrow Path. Use SameSite=None only together with Secure."
                    ),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
                    url=home.url,
                )
            )

        same_site = ""
        for attr in attributes:
            if attr.startswith("samesite="):
                same_site = attr.split("=", 1)[1].strip()
        if same_site == "none" and "secure" not in attr_names:
            findings.append(
                Finding(
                    check="cookies",
                    title="Cookie '%s' uses SameSite=None without Secure" % name,
                    severity="medium",
                    description="Browsers reject SameSite=None cookies that are not also marked Secure.",
                    evidence=clip(raw),
                    remediation="Add the Secure attribute or use SameSite=Lax.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"],
                    url=home.url,
                )
            )

    return findings


# --------------------------------------------------------------------------- #
# Checks: CORS
# --------------------------------------------------------------------------- #


def check_cors(ctx: ScanContext) -> List[Finding]:
    home = ctx.home
    if not home.ok:
        return []
    probe = "https://vulnhunter-cors-probe.invalid"
    result = ctx.client.request(home.url, headers={"Origin": probe})
    if not result.ok:
        return []
    acao = result.header("access-control-allow-origin").strip()
    acac = result.header("access-control-allow-credentials").strip().lower()
    findings: List[Finding] = []

    if acao == probe:
        credentialed = acac == "true"
        findings.append(
            Finding(
                check="cors",
                title=(
                    "CORS reflects arbitrary origins with credentials"
                    if credentialed
                    else "CORS reflects arbitrary origins"
                ),
                severity="high" if credentialed else "medium",
                description=(
                    "The server echoed an attacker-controlled Origin back in "
                    "Access-Control-Allow-Origin%s, so any website can read "
                    "authenticated responses from this origin."
                    % (" while allowing credentials" if credentialed else "")
                ),
                evidence=(
                    "Origin: %s\nAccess-Control-Allow-Origin: %s\n"
                    "Access-Control-Allow-Credentials: %s"
                    % (probe, acao, acac or "<not set>")
                ),
                remediation=(
                    "Validate Origin against an explicit allowlist and only return that exact "
                    "origin. Never combine a reflected origin with credentials."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html"],
                url=home.url,
            )
        )
    elif acao == "*" and acac == "true":
        findings.append(
            Finding(
                check="cors",
                title="CORS wildcard combined with credentials",
                severity="low",
                description=(
                    "Access-Control-Allow-Origin: * together with credentials is contradictory "
                    "and indicates a confused CORS policy; browsers reject it, but some HTTP "
                    "clients and older stacks do not."
                ),
                evidence="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                remediation="Return a specific origin when credentials are allowed.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                url=home.url,
            )
        )
    elif acao == "null":
        findings.append(
            Finding(
                check="cors",
                title="CORS allows the null origin",
                severity="low",
                description=(
                    "'null' is the origin of sandboxed iframes and data: URLs, and is "
                    "controllable by attackers."
                ),
                evidence="Access-Control-Allow-Origin: null",
                remediation="Remove null from the CORS allowlist and validate explicit origins.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                url=home.url,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Checks: TLS
# --------------------------------------------------------------------------- #


def _tls_probe_connect(host: str, port: int, timeout: float, verify: bool, info: Dict[str, object]) -> None:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            info["version"] = tls.version()
            cipher = tls.cipher()
            if cipher:
                info["cipher"] = cipher[0]
                info["cipher_protocol"] = cipher[1]
                info["bits"] = cipher[2]
            if verify:
                cert = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                if not_after:
                    info["not_after"] = not_after
                    try:
                        expires = ssl.cert_time_to_seconds(not_after)
                        info["expires_in_days"] = int((expires - time.time()) // 86400)
                    except ValueError:  # pragma: no cover - malformed cert date
                        pass


def probe_tls(host: str, port: int, timeout: float = 8.0) -> Dict[str, object]:
    """Best-effort TLS inspection; never raises for network/certificate errors."""
    info: Dict[str, object] = {
        "host": host,
        "port": port,
        "version": None,
        "cipher": None,
        "bits": None,
        "not_after": None,
        "expires_in_days": None,
        "verify_error": "",
        "error": "",
        "legacy_versions": [],
    }
    try:
        _tls_probe_connect(host, port, timeout, True, info)
    except ssl.SSLCertVerificationError as exc:
        info["verify_error"] = str(exc)
        try:
            _tls_probe_connect(host, port, timeout, False, info)
        except (OSError, ssl.SSLError) as retry_exc:
            info["error"] = str(retry_exc)
            return info
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)
        return info

    legacy: List[str] = []
    for label, attribute in (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1")):
        version = getattr(ssl.TLSVersion, attribute, None)
        if version is None:  # removed in a future interpreter
            continue
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = version
                context.maximum_version = version
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ssl.SSLError, ValueError):  # pragma: no cover - old OpenSSL
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    pass
            legacy.append(label)
        except (OSError, ssl.SSLError):
            continue
    info["legacy_versions"] = legacy
    return info


def evaluate_tls(info: Dict[str, object], url: str) -> List[Finding]:
    """Turn probe output into findings. Pure: no network access."""
    findings: List[Finding] = []
    if info.get("error"):
        return findings

    if info.get("verify_error"):
        findings.append(
            Finding(
                check="tls",
                title="TLS certificate is not trusted",
                severity="high",
                description=(
                    "Certificate validation failed, so clients cannot authenticate this "
                    "server. This indicates an expired, self-signed, mismatched or "
                    "incompletely chained certificate."
                ),
                evidence=clip(str(info["verify_error"]), 400),
                remediation=(
                    "Install a certificate from a trusted CA for every served hostname and "
                    "serve the full intermediate chain."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                url=url,
            )
        )

    version = str(info.get("version") or "")
    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(
            Finding(
                check="tls",
                title="Obsolete TLS version negotiated",
                severity="high",
                description=(
                    "The server negotiated %s, which is deprecated and no longer receives "
                    "security fixes." % version
                ),
                evidence="Negotiated protocol: %s" % version,
                remediation="Require TLS 1.2 or newer and disable TLS 1.0/1.1 and SSLv3.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                url=url,
            )
        )

    legacy = info.get("legacy_versions") or []
    if legacy:
        findings.append(
            Finding(
                check="tls",
                title="Legacy TLS versions accepted",
                severity="high",
                description=(
                    "The server completed handshakes using %s even though modern clients "
                    "do not need them." % ", ".join(str(v) for v in legacy)
                ),
                evidence="Accepted: %s" % ", ".join(str(v) for v in legacy),
                remediation="Configure the listener to allow only TLS 1.2 and TLS 1.3.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                url=url,
            )
        )

    days = info.get("expires_in_days")
    if isinstance(days, int):
        if days < 0:
            findings.append(
                Finding(
                    check="tls",
                    title="TLS certificate has expired",
                    severity="high",
                    description="The certificate expired %d days ago." % abs(days),
                    evidence="notAfter: %s" % info.get("not_after", "unknown"),
                    remediation="Renew the certificate and automate renewal.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    url=url,
                )
            )
        elif days < 14:
            findings.append(
                Finding(
                    check="tls",
                    title="TLS certificate expires soon",
                    severity="medium",
                    description="The certificate expires in %d day(s)." % days,
                    evidence="notAfter: %s" % info.get("not_after", "unknown"),
                    remediation="Renew now and automate renewal (e.g. ACME).",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    url=url,
                )
            )
        elif days < 30:
            findings.append(
                Finding(
                    check="tls",
                    title="TLS certificate expires within 30 days",
                    severity="low",
                    description="The certificate expires in %d day(s)." % days,
                    evidence="notAfter: %s" % info.get("not_after", "unknown"),
                    remediation="Confirm automated renewal is working.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    url=url,
                )
            )

    cipher = str(info.get("cipher") or "").upper()
    weak_tokens = ("RC4", "3DES", "DES-CBC", "_DES_", "NULL", "EXPORT", "MD5", "IDEA")
    matched = [token for token in weak_tokens if token in cipher]
    if matched:
        findings.append(
            Finding(
                check="tls",
                title="Weak TLS cipher suite negotiated",
                severity="high",
                description="The negotiated cipher suite uses primitives considered broken.",
                evidence="Cipher: %s" % info.get("cipher"),
                remediation="Remove RC4/3DES/DES/NULL/EXPORT suites from the TLS configuration.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                url=url,
            )
        )

    bits = info.get("bits")
    if isinstance(bits, int) and bits < 112 and not matched:
        findings.append(
            Finding(
                check="tls",
                title="TLS cipher has insufficient key strength",
                severity="medium",
                description="The negotiated cipher provides only %d bits of security." % bits,
                evidence="Cipher: %s (%d bits)" % (info.get("cipher"), bits),
                remediation="Prefer AEAD suites with at least 128-bit keys.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                url=url,
            )
        )

    return findings


def check_tls(ctx: ScanContext) -> List[Finding]:
    parsed = ctx.parsed
    if parsed.scheme != "https" or not parsed.hostname:
        return []
    port = parsed.port or 443
    info = probe_tls(parsed.hostname, port, ctx.client.timeout)
    return evaluate_tls(info, ctx.url)


# --------------------------------------------------------------------------- #
# Checks: transport encryption
# --------------------------------------------------------------------------- #


def check_transport(ctx: ScanContext) -> List[Finding]:
    parsed = ctx.parsed
    if not parsed.hostname:
        return []
    findings: List[Finding] = []
    hostname = parsed.hostname

    if parsed.scheme == "https":
        http_url = urllib.parse.urlunparse(
            ("http", parsed.netloc, parsed.path or "/", parsed.query, "", "")
        )
        result = ctx.client.request(http_url)
        if result.ok and result.status is not None and result.status < 400:
            findings.append(
                Finding(
                    check="transport",
                    title="Plaintext HTTP version of the site is reachable",
                    severity="medium",
                    description=(
                        "http:// serves content directly instead of redirecting to https://, "
                        "so the first request (and any cookie sent with it) can be intercepted."
                    ),
                    evidence="HTTP/1.x %s %s" % (result.status, http_url),
                    remediation="Redirect every HTTP request to HTTPS with a 301 and enable HSTS.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    url=http_url,
                )
            )
        return findings

    # Target is plaintext: see whether TLS is available at all.
    candidate_ports = [parsed.port] if parsed.port else [443]
    tls_available = False
    for port in candidate_ports:
        info = probe_tls(hostname, port, min(ctx.client.timeout, 5.0))
        if not info.get("error"):
            tls_available = True
            findings.append(
                Finding(
                    check="transport",
                    title="Site is served over plaintext HTTP",
                    severity="medium",
                    description=(
                        "The scanned URL uses http:// and no redirect to HTTPS was observed; "
                        "traffic is readable and modifiable in transit."
                    ),
                    evidence="Scheme: http, HTTPS available on port %d" % port,
                    remediation="Serve everything over HTTPS and redirect HTTP clients with a 301.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    url=ctx.url,
                )
            )
            break
    if not tls_available:
        findings.append(
            Finding(
                check="transport",
                title="No TLS available on the scanned port",
                severity="high",
                description=(
                    "The target answers over plaintext HTTP and no TLS listener was found, "
                    "so every request and response is exposed on the network."
                ),
                evidence="Scheme: http, TLS probe failed on port(s): %s"
                % ", ".join(str(p) for p in candidate_ports),
                remediation="Terminate TLS in front of the application and redirect HTTP to HTTPS.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                url=ctx.url,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Checks: exposed paths
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class PathProbe:
    path: str
    severity: str
    title: str
    signature: str
    description: str
    remediation: str
    references: List[str] = dataclasses.field(default_factory=list)


PATH_CANDIDATES: Tuple[PathProbe, ...] = (
    PathProbe(
        "/.git/HEAD",
        "high",
        "Exposed Git repository metadata",
        r"^ref:\s+refs/",
        "The .git directory is publicly readable, which allows an attacker to "
        "reconstruct source code, credentials and history.",
        "Block access to .git/ at the web server and redeploy from a clean build artifact.",
        ["https://cwe.mitre.org/data/definitions/538.html"],
    ),
    PathProbe(
        "/.env",
        "critical",
        "Exposed environment file",
        r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=",
        "An environment file containing configuration and likely secrets is served "
        "publicly. Treat every value in it as compromised.",
        "Deny access to dotfiles, rotate all exposed secrets, and keep .env outside the document root.",
        ["https://cwe.mitre.org/data/definitions/538.html"],
    ),
    PathProbe(
        "/.htaccess",
        "low",
        "Readable Apache .htaccess",
        r"(?im)^\s*(<IfModule|RewriteEngine|AuthType|Require\s)",
        "Server configuration is readable, which leaks rewrite rules and protected paths.",
        "Deny access to .ht* files in the server configuration.",
        ["https://cwe.mitre.org/data/definitions/538.html"],
    ),
    PathProbe(
        "/package.json",
        "low",
        "Exposed Node.js package manifest",
        r'"name"\s*:\s*"[^"]+"',
        "The dependency manifest is public, disclosing the exact packages and versions in use.",
        "Serve only the built front-end assets, not project metadata files.",
        ["https://cwe.mitre.org/data/definitions/200.html"],
    ),
    PathProbe(
        "/server-status",
        "medium",
        "Apache server-status page exposed",
        r"Apache Server Status",
        "mod_status output is public and leaks request paths, client IPs and server internals.",
        "Restrict /server-status to localhost or disable mod_status.",
        ["https://cwe.mitre.org/data/definitions/200.html"],
    ),
    PathProbe(
        "/phpinfo.php",
        "medium",
        "phpinfo() page exposed",
        r"(?i)phpinfo\(\)|PHP Version",
        "A phpinfo() page discloses PHP version, loaded extensions, paths and environment variables.",
        "Remove the file and never deploy diagnostics to production.",
        ["https://cwe.mitre.org/data/definitions/200.html"],
    ),
    PathProbe(
        "/actuator/env",
        "high",
        "Spring Boot Actuator environment exposed",
        r'"propertySources"',
        "Actuator environment data is public and can include datasource passwords and tokens.",
        "Expose Actuator on an internal management port and require authentication.",
        ["https://cwe.mitre.org/data/definitions/538.html"],
    ),
    PathProbe(
        "/.DS_Store",
        "low",
        "macOS .DS_Store exposed",
        r"Bud1",
        "A Finder metadata file is public and leaks the names of files in the directory.",
        "Deny access to .DS_Store files and remove them from deployment artifacts.",
        ["https://cwe.mitre.org/data/definitions/538.html"],
    ),
    PathProbe(
        "/backup.zip",
        "high",
        "Backup archive exposed",
        r"^PK\x03\x04",
        "A downloadable backup archive was found. Archives typically contain source, "
        "configuration and database dumps.",
        "Serve backups from a private bucket and require authentication.",
        ["https://cwe.mitre.org/data/definitions/530.html"],
    ),
    PathProbe(
        "/.svn/wc.db",
        "high",
        "Exposed Subversion metadata",
        r"^SQLite format 3",
        "Subversion working copy metadata is public, which allows source reconstruction.",
        "Block access to .svn/ and deploy without working copy metadata.",
        ["https://cwe.mitre.org/data/definitions/538.html"],
    ),
)


def check_paths(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    token = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    baseline = ctx.client.request(ctx.path_url("/vulnhunter-%s.txt" % token))
    baseline_body = baseline.body if baseline.status == 200 else None

    for probe in PATH_CANDIDATES[: ctx.max_paths]:
        url = ctx.path_url(probe.path)
        result = ctx.client.request(url)
        if result.status != 200 or result.header("content-type").lower().startswith(
            ("image/", "font/", "audio/", "video/")
        ):
            continue
        if baseline_body is not None and result.body == baseline_body:
            continue  # same catch-all page as a random URL: soft 404
        text = result.text()
        match = re.search(probe.signature, text)
        if not match:
            continue
        line = text[max(0, match.start() - 40) : match.end() + 80]
        findings.append(
            Finding(
                check="paths",
                title=probe.title,
                severity=probe.severity,
                description=probe.description,
                evidence="GET %s -> %s\n%s" % (probe.path, result.status, _first_lines(line, 2)),
                remediation=probe.remediation,
                references=list(probe.references),
                url=url,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Checks: HTTP methods
# --------------------------------------------------------------------------- #


def check_methods(ctx: ScanContext) -> List[Finding]:
    if not ctx.home.ok:
        return []
    findings: List[Finding] = []
    url = ctx.home.url

    options = ctx.client.request(url, method="OPTIONS")
    if options.ok:
        allow = options.header("allow")
        if allow:
            verbs = [v.strip().upper() for v in allow.split(",") if v.strip()]
            risky = [v for v in verbs if v in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")]
            if risky:
                findings.append(
                    Finding(
                        check="methods",
                        title="Potentially dangerous HTTP methods advertised",
                        severity="low",
                        description=(
                            "The OPTIONS response advertises methods that change or tunnel "
                            "state. Verify each is intentional and authenticated."
                        ),
                        evidence="Allow: %s" % clip(allow),
                        remediation="Disable unused methods (PUT, DELETE, TRACE, CONNECT) at the server or CDN.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Methods_Cheat_Sheet.html"],
                        url=url,
                    )
                )

    trace = ctx.client.request(url, method="TRACE")
    if trace.status == 200 and re.search(r"TRACE\s+/", trace.text(4096), re.IGNORECASE):
        findings.append(
            Finding(
                check="methods",
                title="HTTP TRACE method enabled",
                severity="medium",
                description=(
                    "TRACE echoes the request back, which historically enables Cross-Site "
                    "Tracing and can bypass HttpOnly cookies."
                ),
                evidence="TRACE %s -> 200 with request echoed" % url,
                remediation="Disable TRACE (TraceEnable off in Apache, or block it at the proxy).",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                url=url,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Checks: information disclosure
# --------------------------------------------------------------------------- #

_LEAK_PATTERNS = (
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"(?i)\bat\s+[a-z0-9_.$]+\([A-Za-z0-9_]+\.java:\d+\)", "Java stack trace"),
    (r"(?i)You have an error in your SQL syntax", "SQL error message"),
    (r"(?i)ORA-\d{5}", "Oracle error code"),
    (r"(?i)Warning:\s+(include|require|mysql_|pg_connect)", "PHP warning"),
    (r"(?i)System\.(Data|Web|IO)\.[A-Za-z.]+Exception", ".NET exception"),
)

_SENSITIVE_ROBOTS = (
    "admin",
    "backup",
    "config",
    ".git",
    "private",
    "secret",
    "internal",
    "db",
    "sql",
    "staging",
    "test",
    "token",
    "passwd",
)


def check_disclosure(ctx: ScanContext) -> List[Finding]:
    home = ctx.home
    if not home.ok:
        return []
    findings: List[Finding] = []
    url = home.url

    banners: List[str] = []
    for header_name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        value = home.header(header_name).strip()
        if value and re.search(r"\d", value):
            banners.append("%s: %s" % (header_name.title(), value))
    if banners:
        findings.append(
            Finding(
                check="disclosure",
                title="Software version disclosed in response headers",
                severity="low",
                description=(
                    "Version banners tell an attacker exactly which exploits to try, and "
                    "rarely serve any functional purpose."
                ),
                evidence="\n".join(banners),
                remediation="Remove or genericise version banners (ServerTokens Prod, expose_php Off, strip X-Powered-By).",
                references=["https://cwe.mitre.org/data/definitions/200.html"],
                url=url,
            )
        )

    body = home.text(65536)
    listing = re.search(r"(?i)(?:<title>)?\s*Index of /[^<\s]*", body)
    if listing:
        findings.append(
            Finding(
                check="disclosure",
                title="Directory listing enabled",
                severity="medium",
                description=(
                    "The server returns an auto-generated index, which exposes files that "
                    "were never meant to be discovered."
                ),
                evidence=_first_lines(listing.group(0), 1, 160),
                remediation="Disable auto-indexing (Options -Indexes / autoindex off).",
                references=["https://cwe.mitre.org/data/definitions/548.html"],
                url=url,
            )
        )

    token = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    probe = ctx.client.request(ctx.path_url("/vulnhunter-error-%s" % token))
    if probe.ok:
        probe_text = probe.text(65536)
        for pattern, label in _LEAK_PATTERNS:
            match = re.search(pattern, probe_text)
            if match:
                findings.append(
                    Finding(
                        check="disclosure",
                        title="Verbose error output leaks internals",
                        severity="medium",
                        description=(
                            "A request for a non-existent path returned a %s, exposing "
                            "framework and infrastructure details to any visitor."
                        )
                        % label,
                        evidence="HTTP %s\n%s"
                        % (probe.status, _first_lines(probe_text[max(0, match.start() - 60) : match.end() + 160], 3)),
                        remediation="Turn off debug mode in production and return a generic error page.",
                        references=["https://cwe.mitre.org/data/definitions/209.html"],
                        url=probe.url,
                    )
                )
                break

    robots = ctx.client.request(ctx.path_url("/robots.txt"))
    if robots.status == 200:
        robots_text = robots.text(65536)
        hits = sorted({word for word in _SENSITIVE_ROBOTS if re.search(r"(?i)\b%s\b" % re.escape(word), robots_text)})
        if hits:
            findings.append(
                Finding(
                    check="disclosure",
                    title="robots.txt points at sensitive paths",
                    severity="low",
                    description=(
                        "robots.txt is advisory only: listing private areas invites attackers "
                        "to request them directly."
                    ),
                    evidence="Matched: %s\n%s" % (", ".join(hits), _first_lines(robots_text, 3)),
                    remediation="Do not list secrets or admin paths in robots.txt; enforce access control instead.",
                    references=["https://cwe.mitre.org/data/definitions/200.html"],
                    url=robots.url,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Check registry
# --------------------------------------------------------------------------- #

CHECKS: Dict[str, Check] = {
    check.id: check
    for check in (
        Check("headers", "HTTP security headers", check_headers),
        Check("cookies", "Cookie security flags", check_cookies),
        Check("cors", "CORS policy", check_cors),
        Check("tls", "TLS configuration and certificate", check_tls),
        Check("transport", "HTTPS enforcement", check_transport),
        Check("paths", "Commonly exposed files", check_paths),
        Check("methods", "Allowed HTTP methods", check_methods),
        Check("disclosure", "Information disclosure", check_disclosure),
    )
}

DEFAULT_CHECKS = list(CHECKS)


def resolve_checks(selected: Optional[Sequence[str]], skipped: Optional[Sequence[str]] = None) -> List[str]:
    chosen = list(selected) if selected else list(DEFAULT_CHECKS)
    if len(chosen) == 1 and chosen[0] == "all":
        chosen = list(DEFAULT_CHECKS)
    unknown = [c for c in chosen if c not in CHECKS]
    if unknown:
        raise UsageError(
            "unknown check(s): %s (available: %s)" % (", ".join(unknown), ", ".join(DEFAULT_CHECKS))
        )
    for name in skipped or []:
        if name not in CHECKS:
            raise UsageError("unknown check to skip: %s" % name)
        while name in chosen:
            chosen.remove(name)
    if not chosen:
        raise UsageError("no checks selected")
    return chosen


# --------------------------------------------------------------------------- #
# Scan orchestration
# --------------------------------------------------------------------------- #


def scan(target: str, options: Optional[ScanOptions] = None) -> ScanReport:
    options = options or ScanOptions()
    url = normalize_target(target)
    parsed = urllib.parse.urlparse(url)

    if not options.authorized and not is_local_target(parsed.hostname or ""):
        raise AuthorizationError(
            "%s is not a local address. Only scan systems you own or have written "
            "permission to test; re-run with --authorized to confirm you do." % parsed.hostname
        )

    checks = resolve_checks(options.checks)
    started_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    start = time.monotonic()
    client = HttpClient(
        timeout=options.timeout,
        user_agent=options.user_agent,
        verify=options.verify_tls,
        delay=options.delay,
    )

    errors: List[str] = []
    chain = fetch_chain(client, url)
    home = chain[-1] if chain else HttpResult(url=url, error="no response")
    if not home.ok:
        errors.append("request failed: %s" % (home.error or "unknown error"))

    ctx = ScanContext(
        url=url,
        parsed=parsed,
        client=client,
        chain=chain,
        home=home,
        max_paths=max(0, options.max_paths),
        errors=errors,
    )

    findings: List[Finding] = []
    for check_id in checks:
        try:
            findings.extend(CHECKS[check_id].func(ctx))
        except Exception as exc:  # a broken check must not abort the scan
            errors.append("%s: %s: %s" % (check_id, type(exc).__name__, exc))

    deduped: Dict[Tuple[str, str, str, str], Finding] = {}
    for finding in findings:
        deduped.setdefault(
            (finding.check, finding.title, finding.url, finding.evidence), finding
        )
    ordered = sorted(deduped.values(), key=lambda f: f.sort_key())

    return ScanReport(
        target=url,
        final_url=home.url,
        status=home.status,
        redirects=max(0, len(chain) - 1),
        findings=ordered,
        errors=errors,
        checks_run=checks,
        started_at=started_at,
        duration=time.monotonic() - start,
    )


# --------------------------------------------------------------------------- #
# Console report
# --------------------------------------------------------------------------- #


def _use_color(stream, forced: Optional[bool]) -> bool:
    if forced is not None:
        return forced
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def print_report(report: ScanReport, stream=None, color: Optional[bool] = None) -> None:
    stream = stream or sys.stdout
    enabled = _use_color(stream, color)
    summary = report.summary

    def paint(text: str, key: str) -> str:
        if not enabled:
            return text
        return "%s%s%s" % (COLORS.get(key, ""), text, COLORS["reset"])

    lines: List[str] = []
    lines.append(paint("Vulnhunter %s" % VERSION, "bold") + " - authorized web vulnerability scan")
    lines.append("Target:  %s" % report.target)
    lines.append(
        "Final:   %s (HTTP %s, %d redirect(s))"
        % (report.final_url, report.status if report.status is not None else "-", report.redirects)
    )
    lines.append("Checks:  %s" % ", ".join(report.checks_run))
    lines.append("Started: %s (%.2fs)" % (report.started_at, report.duration))
    lines.append("")

    if not report.findings:
        lines.append(paint("No findings.", "low"))
    for finding in report.findings:
        tag = paint("[%-8s]" % finding.severity.upper(), finding.severity)
        lines.append("%s %s" % (tag, paint(finding.title, "bold")))
        lines.append("  URL:   %s" % finding.url)
        for chunk in finding.description.splitlines():
            lines.append("  What:  %s" % chunk)
        if finding.evidence:
            for index, chunk in enumerate(finding.evidence.splitlines()):
                prefix = "  Proof: " if index == 0 else "         "
                lines.append("%s%s" % (prefix, clip(chunk, 300)))
        if finding.remediation:
            lines.append("  Fix:   %s" % clip(finding.remediation, 400))
        if finding.references:
            lines.append("  Refs:  %s" % ", ".join(finding.references))
        lines.append("")

    totals = "  ".join(
        "%d %s" % (summary[name], name) for name in SEVERITY_ORDER if summary[name]
    ) or "none"
    lines.append(paint("Summary: %s  (%d finding(s))" % (totals, len(report.findings)), "bold"))
    if report.errors:
        lines.append(paint("Warnings:", "medium"))
        for error in report.errors:
            lines.append("  - %s" % clip(error, 300))
    stream.write("\n".join(lines).rstrip() + "\n")
    stream.flush()


# --------------------------------------------------------------------------- #
# JSON / HTML reports
# --------------------------------------------------------------------------- #


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


_HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnhunter report - __TARGET__</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         background: #0f1218; color: #e6e9ef; }
  .wrap { max-width: 1040px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .meta { color: #93a0b4; font-size: 13px; margin-bottom: 24px; }
  .meta code { color: #cfd7e4; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .card { border: 1px solid #232a36; border-radius: 10px; padding: 12px 14px; background: #141922; }
  .card .n { font-size: 24px; font-weight: 650; }
  .card .l { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #8b98ac; }
  .critical .n { color: #f472b6; } .high .n { color: #f87171; } .medium .n { color: #fbbf24; }
  .low .n { color: #60a5fa; } .info .n { color: #a5b4fc; }
  .finding { border: 1px solid #232a36; border-left-width: 4px; border-radius: 10px;
             padding: 16px 18px; margin-bottom: 14px; background: #141922; }
  .finding.critical { border-left-color: #f472b6; } .finding.high { border-left-color: #f87171; }
  .finding.medium { border-left-color: #fbbf24; } .finding.low { border-left-color: #60a5fa; }
  .finding.info { border-left-color: #a5b4fc; }
  .finding h2 { font-size: 16px; margin: 0 0 6px; }
  .seat { display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 0.09em;
          text-transform: uppercase; padding: 2px 8px; border-radius: 999px; margin-bottom: 8px; }
  .seat.critical { background: #4a1030; color: #f9a8d4; } .seat.high { background: #451a1a; color: #fca5a5; }
  .seat.medium { background: #453309; color: #fcd34d; } .seat.low { background: #172c4a; color: #93c5fd; }
  .seat.info { background: #232647; color: #c7d2fe; }
  .finding p { margin: 6px 0; color: #c2cbda; }
  .finding .url { font-size: 12px; color: #8b98ac; word-break: break-all; }
  .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: #8b98ac; margin-top: 12px; }
  pre { background: #0b0e13; border: 1px solid #232a36; border-radius: 8px; padding: 10px 12px;
        overflow-x: auto; font-size: 12px; color: #d5dceb; white-space: pre-wrap; word-break: break-word; }
  a { color: #7dd3fc; }
  .errors { margin-top: 28px; border: 1px solid #4a3a12; background: #221a08; border-radius: 10px; padding: 14px 18px; }
  .errors h2 { font-size: 14px; margin: 0 0 8px; color: #fcd34d; }
  .errors li { font-size: 13px; color: #d9cfae; }
  footer { margin-top: 32px; color: #6b7789; font-size: 12px; }
</style>
</head>
<body>
<div class="wrap">
"""

_HTML_TAIL = """</div>
</body>
</html>
"""


def render_html(report: ScanReport) -> str:
    esc = html.escape
    summary = report.summary
    parts: List[str] = [_HTML_HEAD.replace("__TARGET__", esc(report.target))]
    parts.append("<h1>Vulnhunter report</h1>")
    parts.append(
        '<div class="meta">Target <code>%s</code> &middot; final URL <code>%s</code> '
        "&middot; HTTP %s &middot; %d redirect(s)<br>"
        "Scanned %s in %.2fs with checks: %s</div>"
        % (
            esc(report.target),
            esc(report.final_url),
            esc(str(report.status if report.status is not None else "-")),
            report.redirects,
            esc(report.started_at),
            report.duration,
            esc(", ".join(report.checks_run)),
        )
    )

    parts.append('<div class="cards">')
    for name in SEVERITY_ORDER:
        parts.append(
            '<div class="card %s"><div class="n">%d</div><div class="l">%s</div></div>'
            % (name, summary.get(name, 0), name)
        )
    parts.append("</div>")

    if not report.findings:
        parts.append("<p>No findings.</p>")

    for finding in report.findings:
        parts.append('<section class="finding %s">' % esc(finding.severity))
        parts.append('<div class="seat %s">%s</div>' % (esc(finding.severity), esc(finding.severity)))
        parts.append("<h2>%s</h2>" % esc(finding.title))
        parts.append('<div class="url">%s</div>' % esc(finding.url))
        parts.append("<p>%s</p>" % esc(finding.description).replace("\n", "<br>"))
        if finding.evidence:
            parts.append('<div class="label">Evidence</div><pre>%s</pre>' % esc(finding.evidence))
        if finding.remediation:
            parts.append('<div class="label">Remediation</div><p>%s</p>' % esc(finding.remediation))
        if finding.references:
            links = " &middot; ".join(
                '<a href="%s" rel="noreferrer noopener">%s</a>' % (esc(ref), esc(ref))
                for ref in finding.references
            )
            parts.append('<div class="label">References</div><p>%s</p>' % links)
        parts.append("</section>")

    if report.errors:
        parts.append('<div class="errors"><h2>Scan warnings</h2><ul>')
        for error in report.errors:
            parts.append("<li>%s</li>" % esc(error))
        parts.append("</ul></div>")

    parts.append(
        "<footer>Generated by Vulnhunter %s. Findings are heuristics from a read-only "
        "scan; verify each one before acting on it.</footer>" % esc(VERSION)
    )
    parts.append(_HTML_TAIL)
    return "".join(parts)


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
# GitHub maps these to critical (>=9.0), high (7.0-8.9), medium (4.0-6.9) and
# low (0.1-3.9) code scanning severities. Informational findings get none.
SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
}


def _sarif_slug(text: str) -> str:
    """Stable, dynamic-part-free rule slug (cookie names, hosts and quotes dropped)."""
    text = re.sub(r"'[^']*'", "", text)
    text = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").upper()
    return text or "FINDING"


def sarif_rule_id(finding: Finding) -> str:
    return "VH-%s-%s" % (finding.check.upper(), _sarif_slug(finding.title))


def _sarif_uri(url: str) -> str:
    return urllib.parse.quote(url, safe=":/?#[]@!$&%'()*+,;=-._~")


def _normalize_artifact_path(path: str) -> str:
    """Validate and normalise a repository-relative SARIF artifact path."""
    cleaned = path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise UsageError("--sarif-location must not be empty")
    if "://" in cleaned or cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise UsageError(
            "--sarif-location must be a repository-relative path such as "
            ".github/workflows/scan.yml, not an absolute path or URL"
        )
    return cleaned


def _sarif_end_time(report: ScanReport) -> str:
    try:
        start = datetime.datetime.strptime(report.started_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:  # pragma: no cover - defensive
        return report.started_at
    end = start + datetime.timedelta(seconds=report.duration)
    return end.strftime("%Y-%m-%dT%H:%M:%SZ")


def render_sarif(report: ScanReport, artifact_path: Optional[str] = None) -> str:
    """Render a SARIF 2.1.0 log suitable for GitHub code scanning upload.

    GitHub code scanning only displays a result when its physical location is a
    repository-relative path that exists in the scanned commit. Pass
    ``artifact_path`` (e.g. the workflow or deploy file that defines the scanned
    target) to attach every finding to that file. Without it, results carry the
    scanned URL, which is valid SARIF but is not displayed by code scanning.
    """
    if artifact_path is not None:
        artifact_path = _normalize_artifact_path(artifact_path)
    rules: List[Dict[str, object]] = []
    rule_index: Dict[str, int] = {}
    results: List[Dict[str, object]] = []

    for finding in report.findings:
        rule_id = sarif_rule_id(finding)
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            references = [str(ref) for ref in finding.references if ref]
            help_parts = [finding.description, "", "Remediation: %s" % finding.remediation]
            if references:
                help_parts.append("")
                help_parts.append("References:")
                help_parts.extend("- %s" % ref for ref in references)
            rule: Dict[str, object] = {
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {"text": "\n".join(help_parts), "markdown": "\n".join(help_parts)},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(finding.severity, "note")},
                "properties": {
                    "tags": ["security", finding.check],
                    "precision": "medium",
                },
            }
            severity_score = SARIF_SECURITY_SEVERITY.get(finding.severity)
            if severity_score:
                rule["properties"]["security-severity"] = severity_score  # type: ignore[index]
            if references:
                rule["helpUri"] = references[0]
            rules.append(rule)

        fingerprint = hashlib.sha256(
            ("%s|%s|%s" % (rule_id, finding.url, finding.title)).encode("utf-8")
        ).hexdigest()[:32]
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": SARIF_LEVEL.get(finding.severity, "note"),
                "message": {"text": finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _sarif_uri(artifact_path or finding.url)
                            },
                        }
                    }
                ],
                "partialFingerprints": {"vulnhunter/finding/v1": fingerprint},
                "properties": {
                    "severity": finding.severity,
                    "check": finding.check,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                },
            }
        )

    driver: Dict[str, object] = {
        "name": "Vulnhunter",
        "version": VERSION,
        "informationUri": "https://github.com/fuckeyebrows1/Vulnhunter.py",
        "rules": rules,
    }
    run: Dict[str, object] = {
        "tool": {"driver": driver},
        "invocations": [
            {
                "executionSuccessful": not report.errors,
                "startTimeUtc": report.started_at,
                "endTimeUtc": _sarif_end_time(report),
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": error}} for error in report.errors
                ],
            }
        ],
        "results": results,
        "properties": {
            "target": report.target,
            "finalUrl": report.final_url,
            "checksRun": list(report.checks_run),
            "summary": report.summary,
        },
    }
    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(log, indent=2, ensure_ascii=False) + "\n"


def report_basename(report: ScanReport) -> str:
    host = urllib.parse.urlparse(report.target).hostname or "target"
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", host).strip("-") or "target"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "vulnhunter-%s-%s" % (safe, stamp)


def write_reports(
    report: ScanReport,
    json_path: Optional[str] = None,
    html_path: Optional[str] = None,
    sarif_path: Optional[str] = None,
    sarif_location: Optional[str] = None,
) -> List[str]:
    written: List[str] = []
    renderers: List[Tuple[str, str]] = []
    if json_path:
        renderers.append((json_path, render_json(report)))
    if html_path:
        renderers.append((html_path, render_html(report)))
    if sarif_path:
        renderers.append((sarif_path, render_sarif(report, sarif_location)))
    for path, content in renderers:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        written.append(path)
    return written


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnhunter.py",
        description="Authorized, read-only web application vulnerability scanner.",
        epilog=(
            "Examples:\n"
            "  python3 vulnhunter.py https://staging.example.com --authorized\n"
            "  python3 vulnhunter.py https://staging.example.com --authorized --html report.html\n"
            "  python3 vulnhunter.py http://127.0.0.1:8080 --checks headers,cors --json out.json\n"
            "  python3 vulnhunter.py --list-checks\n\n"
            "Only scan systems you own or have written permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="URL to scan (https:// is assumed if omitted)")
    parser.add_argument("--version", action="version", version="Vulnhunter %s" % VERSION)
    parser.add_argument(
        "-a",
        "--authorized",
        action="store_true",
        help="confirm you are authorized to test this target (required for non-local hosts)",
    )
    parser.add_argument(
        "--checks",
        default="all",
        help="comma-separated checks to run, or 'all' (default). See --list-checks",
    )
    parser.add_argument("--skip-checks", default="", help="comma-separated checks to skip")
    parser.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    parser.add_argument("--json", metavar="PATH", help="write a JSON report to PATH")
    parser.add_argument("--html", metavar="PATH", help="write a self-contained HTML report to PATH")
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        help="write a SARIF 2.1.0 report to PATH for GitHub code scanning",
    )
    parser.add_argument(
        "--sarif-location",
        metavar="REPO_PATH",
        help=(
            "repository-relative file to attach SARIF results to, e.g. "
            ".github/workflows/vulnhunter.yml; GitHub code scanning only displays "
            "results whose location is a file in the scanned commit"
        ),
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        metavar="DIR",
        help="write JSON, HTML and SARIF reports into DIR",
    )
    parser.add_argument(
        "--timeout", type=float, default=8.0, help="per-request timeout in seconds (default: 8)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="seconds to wait between requests, for politeness (default: 0.1)",
    )
    parser.add_argument("--max-paths", type=int, default=len(PATH_CANDIDATES), help="number of path probes")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent header to send")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify TLS certificates while scanning (still reported as a finding)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none",) + SEVERITY_ORDER,
        default="none",
        help="exit with status 2 when a finding at or above this severity exists (default: none)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colours (also honoured via NO_COLOR)",
    )
    return parser


def _parse_csv(value: str) -> List[str]:
    return [item.strip().lower() for item in (value or "").split(",") if item.strip()]


def list_checks(stream=None) -> None:
    stream = stream or sys.stdout
    rows = [("CHECK", "DESCRIPTION")] + [(c.id, c.name) for c in CHECKS.values()]
    width = max(len(row[0]) for row in rows) + 2
    for ident, name in rows:
        stream.write("%-*s%s\n" % (width, ident, name))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        list_checks()
        return 0
    if not args.target:
        parser.error("the target URL is required")

    try:
        checks = resolve_checks(_parse_csv(args.checks), _parse_csv(args.skip_checks))
        sarif_location = (
            _normalize_artifact_path(args.sarif_location) if args.sarif_location else None
        )
    except UsageError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    if sarif_location and not (args.sarif or args.output_dir):
        sys.stderr.write("error: --sarif-location requires --sarif or --output-dir\n")
        return 1

    options = ScanOptions(
        checks=checks,
        timeout=max(0.5, args.timeout),
        delay=max(0.0, args.delay),
        verify_tls=not args.insecure,
        user_agent=args.user_agent,
        max_paths=args.max_paths,
        authorized=args.authorized,
    )

    try:
        report = scan(args.target, options)
    except AuthorizationError as exc:
        sys.stderr.write("refusing to scan: %s\n" % exc)
        return 1
    except UsageError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    print_report(report, color=False if args.no_color else None)

    json_path = args.json
    html_path = args.html
    sarif_path = args.sarif
    if args.output_dir:
        base = os.path.join(args.output_dir, report_basename(report))
        json_path = json_path or base + ".json"
        html_path = html_path or base + ".html"
        sarif_path = sarif_path or base + ".sarif"
    try:
        written = write_reports(report, json_path, html_path, sarif_path, sarif_location)
    except OSError as exc:
        sys.stderr.write("error: could not write report: %s\n" % exc)
        return 1
    for path in written:
        sys.stdout.write("Report written: %s\n" % path)

    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in report.findings):
            return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
