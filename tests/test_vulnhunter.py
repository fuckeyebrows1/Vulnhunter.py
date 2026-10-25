"""Tests for Vulnhunter.

Everything runs offline against a local fixture HTTP server; no external network
access is required or performed.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import vulnhunter as vh  # noqa: E402

SPA_PAGE = "<html><head><title>Home</title></head><body>app shell</body></html>"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output clean
        pass

    def _respond(self, include_body=True):
        route = self.server.routes.get(self.path.split("?")[0])
        if route is None:
            route = self.server.default
        if callable(route):
            route = route(self)
        status, headers, body = route
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        pairs = headers.items() if isinstance(headers, dict) else headers
        for key, value in pairs:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body and body:
            self.wfile.write(body)

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond(include_body=False)

    def do_OPTIONS(self):
        status, headers, body = self.server.options
        self.send_response(status)
        pairs = headers.items() if isinstance(headers, dict) else headers
        for key, value in pairs:
            self.send_header(key, value)
        body = body.encode() if isinstance(body, str) else body
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_TRACE(self):
        status, headers, body = self.server.trace
        self.send_response(status)
        pairs = headers.items() if isinstance(headers, dict) else headers
        for key, value in pairs:
            self.send_header(key, value)
        body = body.encode() if isinstance(body, str) else body
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


def _handler_class(server_version="TestServer/1.2.3"):
    return type("FixtureHandler", (_Handler,), {"server_version": server_version, "sys_version": ""})


class FixtureServer:
    def __init__(self, routes=None, default=None, options=None, trace=None, server_version="TestServer/1.2.3"):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler_class(server_version))
        self.httpd.routes = dict(routes or {})
        self.httpd.default = default or (
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            SPA_PAGE,
        )
        self.httpd.options = options or (200, {"Allow": "GET, HEAD, POST"}, "")
        self.httpd.trace = trace or (501, {"Content-Type": "text/plain"}, "not implemented")
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc_info):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=5)


def run_scan(fixture, checks=None, max_paths=4):
    options = vh.ScanOptions(
        checks=checks or ["headers"],
        delay=0.0,
        timeout=5.0,
        max_paths=max_paths,
        authorized=False,
    )
    return vh.scan(fixture.url, options)


class HeaderTests(unittest.TestCase):
    def test_missing_headers_are_reported(self):
        with FixtureServer() as fixture:
            report = run_scan(fixture)
        titles = {f.title for f in report.findings}
        self.assertIn("Content-Security-Policy header missing", titles)
        self.assertIn("Clickjacking protection missing", titles)
        self.assertIn("X-Content-Type-Options missing or invalid", titles)
        self.assertIn("Referrer-Policy header missing", titles)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.status, 200)

    def test_hardened_headers_produce_no_findings(self):
        headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=(), microphone=()"),
        ]
        with FixtureServer(routes={"/": (200, headers, SPA_PAGE)}) as fixture:
            report = run_scan(fixture)
        self.assertEqual([f.to_dict() for f in report.findings], [])

    def test_weak_csp_detected(self):
        headers = [
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "camera=()"),
        ]
        with FixtureServer(routes={"/": (200, headers, SPA_PAGE)}) as fixture:
            report = run_scan(fixture)
        titles = [f.title for f in report.findings]
        self.assertIn("Content-Security-Policy allows unsafe script sources", titles)


class CookieTests(unittest.TestCase):
    def test_insecure_cookies_flagged(self):
        headers = [
            ("Content-Type", "text/html"),
            ("Set-Cookie", "session=abc123; Path=/"),
            ("Set-Cookie", "theme=dark; Path=/; SameSite=None"),
        ]
        with FixtureServer(routes={"/": (200, headers, SPA_PAGE)}) as fixture:
            report = run_scan(fixture, checks=["cookies"])
        titles = [f.title for f in report.findings]
        self.assertIn("Cookie 'session' is missing security attributes", titles)
        self.assertIn("Cookie 'theme' is missing security attributes", titles)
        self.assertIn("Cookie 'theme' uses SameSite=None without Secure", titles)

    def test_hardened_cookie_passes(self):
        headers = [
            ("Content-Type", "text/html"),
            ("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"),
        ]
        with FixtureServer(routes={"/": (200, headers, SPA_PAGE)}) as fixture:
            report = run_scan(fixture, checks=["cookies"])
        self.assertEqual(report.findings, [])


class CorsTests(unittest.TestCase):
    def test_reflected_origin_with_credentials(self):
        def route(handler):
            return (
                200,
                [
                    ("Content-Type", "text/html"),
                    ("Access-Control-Allow-Origin", handler.headers.get("Origin", "")),
                    ("Access-Control-Allow-Credentials", "true"),
                ],
                SPA_PAGE,
            )

        with FixtureServer(routes={"/": route}) as fixture:
            report = run_scan(fixture, checks=["cors"])
        matching = [f for f in report.findings if f.check == "cors"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "high")
        self.assertIn("credentials", matching[0].title)

    def test_no_cors_headers_no_findings(self):
        with FixtureServer() as fixture:
            report = run_scan(fixture, checks=["cors"])
        self.assertEqual(report.findings, [])


class PathTests(unittest.TestCase):
    def test_exposed_files_detected(self):
        routes = {
            "/.git/HEAD": (200, {"Content-Type": "text/plain"}, "ref: refs/heads/main\n"),
            "/.env": (200, {"Content-Type": "text/plain"}, "SECRET_KEY=abc123\nDEBUG=true\n"),
        }
        with FixtureServer(routes=routes) as fixture:
            report = run_scan(fixture, checks=["paths"])
        by_path = {f.url: f for f in report.findings}
        git_url = fixture.url + "/.git/HEAD"
        env_url = fixture.url + "/.env"
        self.assertIn(git_url, by_path)
        self.assertIn(env_url, by_path)
        self.assertEqual(by_path[git_url].severity, "high")
        self.assertEqual(by_path[env_url].severity, "critical")

    def test_soft_404_is_not_flagged(self):
        # The default route serves the same HTML for every path (SPA catch-all).
        with FixtureServer() as fixture:
            report = run_scan(fixture, checks=["paths"], max_paths=6)
        self.assertEqual(report.findings, [])

    def test_generic_200_page_is_not_flagged(self):
        routes = {"/.env": (200, {"Content-Type": "text/html"}, "<html>nothing here</html>")}
        with FixtureServer(routes=routes) as fixture:
            report = run_scan(fixture, checks=["paths"])
        self.assertEqual(report.findings, [])


class MethodTests(unittest.TestCase):
    def test_risky_methods_and_trace(self):
        with FixtureServer(
            options=(200, {"Allow": "GET, HEAD, PUT, DELETE, TRACE"}, ""),
            trace=(200, {"Content-Type": "message/http"}, "TRACE / HTTP/1.1\r\nHost: localhost\r\n"),
        ) as fixture:
            report = run_scan(fixture, checks=["methods"])
        titles = [f.title for f in report.findings]
        self.assertIn("Potentially dangerous HTTP methods advertised", titles)
        self.assertIn("HTTP TRACE method enabled", titles)

    def test_safe_methods_only(self):
        with FixtureServer(options=(200, {"Allow": "GET, HEAD"}, "")) as fixture:
            report = run_scan(fixture, checks=["methods"])
        self.assertEqual(report.findings, [])


class DisclosureTests(unittest.TestCase):
    def test_version_banner_and_robots(self):
        routes = {
            "/robots.txt": (
                200,
                {"Content-Type": "text/plain"},
                "User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
            )
        }
        with FixtureServer(routes=routes) as fixture:
            report = run_scan(fixture, checks=["disclosure"])
        titles = [f.title for f in report.findings]
        self.assertIn("Software version disclosed in response headers", titles)
        self.assertIn("robots.txt points at sensitive paths", titles)

    def test_directory_listing(self):
        body = "<html><head><title>Index of /files</title></head><body>...</body></html>"
        with FixtureServer(default=(200, {"Content-Type": "text/html"}, body)) as fixture:
            report = run_scan(fixture, checks=["disclosure"])
        self.assertIn("Directory listing enabled", [f.title for f in report.findings])

    def test_verbose_error(self):
        body = (
            "<html><body><h1>Server Error</h1>"
            "Traceback (most recent call last):\n"
            '  File "/srv/app/views.py", line 42, in index\n'
            "    raise RuntimeError('boom')"
        )
        with FixtureServer(default=(500, {"Content-Type": "text/html"}, body)) as fixture:
            report = run_scan(fixture, checks=["disclosure"])
        self.assertIn("Verbose error output leaks internals", [f.title for f in report.findings])


class TlsEvaluationTests(unittest.TestCase):
    def _info(self, **overrides):
        info = {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "bits": 256,
            "not_after": "Jan  1 00:00:00 2027 GMT",
            "expires_in_days": 120,
            "verify_error": "",
            "error": "",
            "legacy_versions": [],
        }
        info.update(overrides)
        return info

    def test_modern_configuration_is_clean(self):
        self.assertEqual(vh.evaluate_tls(self._info(), "https://example.test/"), [])

    def test_expired_weak_legacy(self):
        findings = vh.evaluate_tls(
            self._info(
                version="TLSv1",
                cipher="DES-CBC3-SHA",
                bits=112,
                expires_in_days=-3,
                legacy_versions=["TLSv1", "TLSv1.1"],
            ),
            "https://example.test/",
        )
        titles = [f.title for f in findings]
        self.assertIn("TLS certificate has expired", titles)
        self.assertIn("Obsolete TLS version negotiated", titles)
        self.assertIn("Legacy TLS versions accepted", titles)
        self.assertIn("Weak TLS cipher suite negotiated", titles)
        self.assertTrue(all(f.severity in ("high", "medium", "low") for f in findings))

    def test_expiring_soon(self):
        findings = vh.evaluate_tls(self._info(expires_in_days=5), "https://example.test/")
        self.assertEqual([f.title for f in findings], ["TLS certificate expires soon"])
        self.assertEqual(findings[0].severity, "medium")

    def test_untrusted_certificate(self):
        findings = vh.evaluate_tls(
            self._info(verify_error="[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate"),
            "https://example.test/",
        )
        self.assertIn("TLS certificate is not trusted", [f.title for f in findings])

    def test_connection_error_reports_nothing(self):
        self.assertEqual(vh.evaluate_tls(self._info(error="connection refused"), "https://x.test/"), [])


class TargetTests(unittest.TestCase):
    def test_normalize_target(self):
        self.assertEqual(vh.normalize_target("example.com"), "https://example.com/")
        self.assertEqual(vh.normalize_target("example.com/path?q=1"), "https://example.com/path?q=1")
        self.assertEqual(vh.normalize_target("http://127.0.0.1:8080"), "http://127.0.0.1:8080/")
        with self.assertRaises(vh.UsageError):
            vh.normalize_target("ftp://example.com")

    def test_local_target_detection(self):
        self.assertTrue(vh.is_local_target("127.0.0.1"))
        self.assertTrue(vh.is_local_target("localhost"))
        self.assertTrue(vh.is_local_target("10.1.2.3"))
        self.assertTrue(vh.is_local_target("192.168.0.10"))
        self.assertTrue(vh.is_local_target("::1"))
        self.assertTrue(vh.is_local_target("app.internal"))
        self.assertFalse(vh.is_local_target("example.com"))
        self.assertFalse(vh.is_local_target("8.8.8.8"))

    def test_public_target_requires_authorization(self):
        with self.assertRaises(vh.AuthorizationError):
            vh.scan("https://example.com", vh.ScanOptions(checks=["headers"]))
        # Authorized scans of public hosts are allowed to proceed past the gate;
        # this test never performs the network request because of the bad check name.
        with self.assertRaises(vh.UsageError):
            vh.scan("https://example.com", vh.ScanOptions(checks=["nope"], authorized=True))

    def test_unknown_check_rejected(self):
        with self.assertRaises(vh.UsageError):
            vh.resolve_checks(["headers", "does-not-exist"])

    def test_skip_checks(self):
        self.assertEqual(
            vh.resolve_checks(["headers", "cors"], ["cors"]),
            ["headers"],
        )


class ReportTests(unittest.TestCase):
    def _report(self):
        finding = vh.Finding(
            check="headers",
            title="XSS in evidence <script>alert(1)</script>",
            severity="high",
            description="Description with <b>markup</b> & ampersand",
            evidence="Server: <script>alert(1)</script>",
            remediation="Escape output",
            references=["https://cwe.mitre.org/data/definitions/79.html"],
            url="https://example.test/?q=<script>",
        )
        return vh.ScanReport(
            target="https://example.test/",
            final_url="https://example.test/",
            status=200,
            redirects=0,
            findings=[finding],
            errors=["paths: TimeoutError: timed out"],
            checks_run=["headers"],
            started_at="2026-01-01T00:00:00Z",
            duration=1.25,
        )

    def test_json_report_round_trips(self):
        payload = json.loads(vh.render_json(self._report()))
        self.assertEqual(payload["tool"], "vulnhunter")
        self.assertEqual(payload["summary"]["high"], 1)
        self.assertEqual(payload["findings"][0]["severity"], "high")
        self.assertEqual(payload["errors"], ["paths: TimeoutError: timed out"])

    def test_html_report_escapes_user_content(self):
        output = vh.render_html(self._report())
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output)
        self.assertIn("Vulnhunter report", output)
        self.assertIn("Scan warnings", output)

    def test_write_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "nested", "report.json")
            html_path = os.path.join(tmp, "report.html")
            sarif_path = os.path.join(tmp, "nested", "report.sarif")
            written = vh.write_reports(self._report(), json_path, html_path, sarif_path)
            self.assertEqual(sorted(written), sorted([json_path, html_path, sarif_path]))
            for path in written:
                self.assertTrue(os.path.getsize(path) > 0)
            with open(json_path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["target"], "https://example.test/")
            with open(sarif_path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["version"], "2.1.0")


class SarifTests(unittest.TestCase):
    def _report(self):
        def finding(check, title, severity, url="https://example.test/", references=None):
            return vh.Finding(
                check=check,
                title=title,
                severity=severity,
                description="%s description" % check,
                evidence="evidence for %s" % check,
                remediation="fix %s" % check,
                references=list(references or []),
                url=url,
            )

        return vh.ScanReport(
            target="https://example.test/",
            final_url="https://example.test/",
            status=200,
            redirects=0,
            findings=[
                finding(
                    "headers",
                    "Content-Security-Policy header missing",
                    "medium",
                    references=["https://cwe.mitre.org/data/definitions/79.html"],
                ),
                finding("cookies", "Cookie 'session' is missing security attributes", "medium"),
                finding("cookies", "Cookie 'theme' is missing security attributes", "low"),
                finding("tls", "TLS certificate is not trusted", "high"),
                finding("transport", "No TLS available on the scanned port", "critical"),
                finding("headers", "Permissions-Policy header missing", "info"),
            ],
            errors=[],
            checks_run=["headers", "cookies", "tls", "transport"],
            started_at="2026-01-01T00:00:00Z",
            duration=2.5,
        )

    def test_log_is_sarif_2_1_0(self):
        log = json.loads(vh.render_sarif(self._report()))
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(log["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
        self.assertEqual(len(log["runs"]), 1)
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Vulnhunter")
        self.assertEqual(run["tool"]["driver"]["version"], vh.VERSION)
        self.assertEqual(len(run["invocations"]), 1)
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(run["invocations"][0]["startTimeUtc"], "2026-01-01T00:00:00Z")
        self.assertEqual(run["invocations"][0]["endTimeUtc"], "2026-01-01T00:00:02Z")

    def test_every_result_maps_to_a_declared_rule(self):
        run = json.loads(vh.render_sarif(self._report()))["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertTrue(rules)
        for result in run["results"]:
            rule = rules[result["ruleIndex"]]
            self.assertEqual(rule["id"], result["ruleId"])
            self.assertTrue(rule["shortDescription"]["text"])
            self.assertIn("level", rule["defaultConfiguration"])

    def test_rule_ids_are_stable_across_dynamic_values(self):
        run = json.loads(vh.render_sarif(self._report()))["runs"][0]
        cookie_results = [r for r in run["results"] if r["properties"]["check"] == "cookies"]
        self.assertEqual(len(cookie_results), 2)
        self.assertEqual(cookie_results[0]["ruleId"], cookie_results[1]["ruleId"])
        self.assertEqual(cookie_results[0]["ruleIndex"], cookie_results[1]["ruleIndex"])
        # 6 findings, but the two cookie findings share one rule.
        self.assertEqual(len(run["results"]), 6)
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 5)
        for result in run["results"]:
            self.assertTrue(result["ruleId"].startswith("VH-"))

    def test_severity_mapping(self):
        run = json.loads(vh.render_sarif(self._report()))["runs"][0]
        by_title = {r["message"]["text"]: r for r in run["results"]}
        self.assertEqual(by_title["TLS certificate is not trusted"]["level"], "error")
        self.assertEqual(by_title["No TLS available on the scanned port"]["level"], "error")
        self.assertEqual(by_title["Content-Security-Policy header missing"]["level"], "warning")
        self.assertEqual(by_title["Permissions-Policy header missing"]["level"], "note")

        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        high_rule = rules[by_title["TLS certificate is not trusted"]["ruleId"]]
        medium_rule = rules[by_title["Content-Security-Policy header missing"]["ruleId"]]
        info_rule = rules[by_title["Permissions-Policy header missing"]["ruleId"]]
        self.assertEqual(high_rule["properties"]["security-severity"], "8.0")
        self.assertEqual(medium_rule["properties"]["security-severity"], "5.5")
        self.assertNotIn("security-severity", info_rule["properties"])
        self.assertIn("security", medium_rule["properties"]["tags"])

    def test_help_uri_and_locations(self):
        run = json.loads(vh.render_sarif(self._report()))["runs"][0]
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        csp_rule = rules["VH-HEADERS-CONTENT-SECURITY-POLICY-HEADER-MISSING"]
        self.assertEqual(csp_rule["helpUri"], "https://cwe.mitre.org/data/definitions/79.html")
        self.assertIn("Remediation", csp_rule["help"]["text"])
        self.assertIn("fix headers", csp_rule["help"]["text"])
        for result in run["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertEqual(uri, "https://example.test/")

    def test_fingerprints_are_deterministic(self):
        first = json.loads(vh.render_sarif(self._report()))["runs"][0]
        second = json.loads(vh.render_sarif(self._report()))["runs"][0]
        prints = [r["partialFingerprints"]["vulnhunter/finding/v1"] for r in first["results"]]
        self.assertEqual(prints, [r["partialFingerprints"]["vulnhunter/finding/v1"] for r in second["results"]])
        self.assertEqual(len(set(prints)), len(prints))

    def test_uri_is_encoded_and_errors_are_notifications(self):
        report = self._report()
        report.findings[0].url = "https://example.test/?q=<script> &x=1"
        report.errors = ["paths: TimeoutError: timed out"]
        run = json.loads(vh.render_sarif(report))["runs"][0]
        uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "https://example.test/?q=%3Cscript%3E%20&x=1")
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        notifications = run["invocations"][0]["toolExecutionNotifications"]
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["level"], "warning")
        self.assertIn("timed out", notifications[0]["message"]["text"])

    def test_artifact_location_attaches_results_to_a_repo_file(self):
        report = self._report()
        with_location = json.loads(
            vh.render_sarif(report, "./.github/workflows/vulnhunter.yml")
        )["runs"][0]
        self.assertEqual(len(with_location["results"]), 6)
        for result in with_location["results"]:
            physical = result["locations"][0]["physicalLocation"]
            self.assertEqual(physical["artifactLocation"]["uri"], ".github/workflows/vulnhunter.yml")
            self.assertNotIn("region", physical)
        # Identity must not change just because the display location did.
        without_location = json.loads(vh.render_sarif(report))["runs"][0]
        self.assertEqual(
            [r["partialFingerprints"] for r in with_location["results"]],
            [r["partialFingerprints"] for r in without_location["results"]],
        )

    def test_absolute_artifact_locations_are_rejected(self):
        for bad in ("/etc/passwd", "https://example.test/scan", "C:\\repo\\scan.yml", " "):
            with self.subTest(location=bad):
                with self.assertRaises(vh.UsageError):
                    vh.render_sarif(self._report(), bad)

    def test_artifact_location_normalisation(self):
        self.assertEqual(vh._normalize_artifact_path("./a/b.yml"), "a/b.yml")
        self.assertEqual(vh._normalize_artifact_path("  .github/scan.yml "), ".github/scan.yml")
        self.assertEqual(vh._normalize_artifact_path(".\\github\\scan.yml"), "github/scan.yml")
        self.assertEqual(vh._normalize_artifact_path(".github\\scan.yml"), ".github/scan.yml")

    def test_empty_report_is_valid(self):
        report = vh.ScanReport(
            target="https://example.test/",
            final_url="https://example.test/",
            status=200,
            redirects=0,
            findings=[],
            errors=[],
            checks_run=["headers"],
            started_at="2026-01-01T00:00:00Z",
            duration=0.1,
        )
        run = json.loads(vh.render_sarif(report))["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])


class CliTests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "vulnhunter.py")] + list(args),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_list_checks(self):
        result = self._run("--list-checks")
        self.assertEqual(result.returncode, 0, result.stderr)
        for check_id in ("headers", "cookies", "cors", "tls", "paths", "methods", "disclosure"):
            self.assertIn(check_id, result.stdout)

    def test_scan_and_write_reports(self):
        with FixtureServer() as fixture, tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "out.json")
            html_path = os.path.join(tmp, "out.html")
            sarif_path = os.path.join(tmp, "out.sarif")
            result = self._run(
                fixture.url,
                "--checks",
                "headers,cors",
                "--delay",
                "0",
                "--no-color",
                "--json",
                json_path,
                "--html",
                html_path,
                "--sarif",
                sarif_path,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("Summary:", result.stdout)
            self.assertIn("Content-Security-Policy header missing", result.stdout)
            self.assertIn("Report written:", result.stdout)
            with open(json_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["tool"], "vulnhunter")
            self.assertGreaterEqual(payload["summary"]["medium"], 1)
            with open(html_path, encoding="utf-8") as handle:
                self.assertIn("<!doctype html>", handle.read())
            with open(sarif_path, encoding="utf-8") as handle:
                sarif = json.load(handle)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertEqual(
                sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                fixture.url + "/",
            )

    def test_sarif_location_flag(self):
        with FixtureServer() as fixture, tempfile.TemporaryDirectory() as tmp:
            sarif_path = os.path.join(tmp, "out.sarif")
            result = self._run(
                fixture.url,
                "--checks",
                "headers",
                "--delay",
                "0",
                "--sarif",
                sarif_path,
                "--sarif-location",
                ".github/workflows/vulnhunter.yml",
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            with open(sarif_path, encoding="utf-8") as handle:
                sarif = json.load(handle)
        for item in sarif["runs"][0]["results"]:
            self.assertEqual(
                item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                ".github/workflows/vulnhunter.yml",
            )

    def test_sarif_location_requires_a_sarif_output(self):
        result = self._run("http://127.0.0.1:9", "--sarif-location", ".github/scan.yml")
        self.assertEqual(result.returncode, 1)
        self.assertIn("--sarif-location requires", result.stderr)

    def test_sarif_location_rejects_absolute_path(self):
        result = self._run(
            "http://127.0.0.1:9", "--sarif", "/tmp/out.sarif", "--sarif-location", "/etc/passwd"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("repository-relative", result.stderr)

    def test_fail_on_threshold(self):
        with FixtureServer() as fixture:
            result = self._run(fixture.url, "--checks", "headers", "--delay", "0", "--fail-on", "medium")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_public_target_without_authorization_fails_fast(self):
        result = self._run("https://example.com", "--checks", "headers")
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing to scan", result.stderr)

    def test_output_dir(self):
        with FixtureServer() as fixture, tempfile.TemporaryDirectory() as tmp:
            result = self._run(fixture.url, "--checks", "headers", "--delay", "0", "-o", tmp)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(len(os.listdir(tmp)), 3)
            self.assertTrue(any(name.endswith(".json") for name in os.listdir(tmp)))
            self.assertTrue(any(name.endswith(".html") for name in os.listdir(tmp)))
            self.assertTrue(any(name.endswith(".sarif") for name in os.listdir(tmp)))


class FullScanTests(unittest.TestCase):
    def test_full_scan_completes_without_check_errors(self):
        with FixtureServer() as fixture:
            options = vh.ScanOptions(delay=0.0, timeout=5.0, max_paths=2, authorized=False)
            report = vh.scan(fixture.url, options)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.checks_run)
        # Plaintext HTTP with no TLS listener is reported by the transport check.
        self.assertIn(
            "No TLS available on the scanned port", [f.title for f in report.findings]
        )

    def test_findings_sorted_by_severity(self):
        routes = {"/.env": (200, {"Content-Type": "text/plain"}, "SECRET_KEY=abc123\n")}
        with FixtureServer(routes=routes) as fixture:
            report = vh.scan(fixture.url, vh.ScanOptions(delay=0.0, timeout=5.0, max_paths=2))
        ranks = [vh.SEVERITY_RANK[f.severity] for f in report.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))
        self.assertEqual(report.findings[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
