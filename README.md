# Vulnhunter.py

An authorized, read-only web application vulnerability scanner in a single Python
file with **no dependencies beyond the standard library**.

Point it at a web target you own (or have written permission to test) and it runs
a small, non-destructive set of checks in about a second, then prints a severity
sorted report and optionally writes JSON and a self-contained HTML file.

```
$ python3 vulnhunter.py https://staging.example.com --authorized
Vulnhunter 1.0.0 - authorized web vulnerability scan
Target:  https://staging.example.com/
Final:   https://staging.example.com/ (HTTP 200, 0 redirect(s))
Checks:  headers, cookies, cors, tls, transport, paths, methods, disclosure
Started: 2026-10-25T20:22:54Z (0.65s)

[HIGH    ] TLS certificate is not trusted
  URL:   https://staging.example.com/
  What:  Certificate validation failed, so clients cannot authenticate this
         server. This indicates an expired, self-signed, mismatched or
         incompletely chained certificate.
  Proof: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: ...
  Fix:   Install a certificate from a trusted CA for every served hostname and
         serve the full intermediate chain.
  Refs:  https://cheatsheetseries.owasp.org/cheatsheets/...

[MEDIUM  ] Content-Security-Policy header missing
  ...

Summary: 1 high  4 medium  3 low  1 info  (9 finding(s))
```

> **Legal.** Scanning a system without permission is illegal in most
> jurisdictions and often violates hosting terms. Vulnhunter refuses to scan
> non-local hosts unless you pass `--authorized`, which is your explicit
> statement that you have permission. Loopback and private addresses
> (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `*.internal`, ...) are allowed
> without the flag so you can test your own dev environment.

## Requirements

Python 3.8 or newer. Nothing else — no `pip install`, no virtualenv.

## Usage

```bash
python3 vulnhunter.py <target> [options]
```

Common invocations:

```bash
# Scan a public staging host you are authorized to test
python3 vulnhunter.py https://staging.example.com --authorized

# Local app, reports written to a directory
python3 vulnhunter.py http://127.0.0.1:8080 -o reports/

# Only specific checks, CI-friendly exit code on medium-or-worse findings
python3 vulnhunter.py https://example.test --authorized \
    --checks headers,cors,tls --fail-on medium --json report.json

# List available checks
python3 vulnhunter.py --list-checks

# Self-signed dev environment: keep scanning, still report the bad certificate
python3 vulnhunter.py https://localhost:8443 --insecure
```

### Options

| Option | Description |
| --- | --- |
| `--authorized`, `-a` | Confirm you may test this non-local target (required for public hosts) |
| `--checks LIST` | Comma separated checks to run, or `all` (default) |
| `--skip-checks LIST` | Checks to leave out |
| `--list-checks` | Print check ids and descriptions |
| `--json PATH` | Write a JSON report |
| `--html PATH` | Write a self-contained HTML report |
| `--sarif PATH` | Write a SARIF 2.1.0 report for GitHub code scanning |
| `--sarif-location REPO_PATH` | Attach SARIF results to a committed repo file (required for code scanning to display them) |
| `-o DIR`, `--output-dir DIR` | Write JSON, HTML and SARIF reports into `DIR` with a timestamped name |
| `--timeout SECONDS` | Per-request timeout (default `8`) |
| `--delay SECONDS` | Politeness delay between requests (default `0.1`) |
| `--max-paths N` | Number of exposed-file probes (default: all 10) |
| `--user-agent STRING` | Override the `User-Agent` header |
| `--insecure` | Do not verify TLS while scanning (the failure is still reported) |
| `--fail-on LEVEL` | Exit `2` when a finding at/above `info`, `low`, `medium`, `high` or `critical` exists |
| `--no-color` | Disable ANSI colours (also honours `NO_COLOR`) |
| `--version` | Print the version |

Exit codes: `0` scan completed, `2` `--fail-on` threshold met, `1` usage or
authorization error, `130` interrupted.

## Checks

| Id | What it looks at | Example findings |
| --- | --- | --- |
| `headers` | HTTP response security headers | Missing HSTS/CSP/`X-Content-Type-Options`/`Referrer-Policy`, clickjacking protection, weak CSP (`unsafe-inline`, `*`, `data:`), short HSTS `max-age` |
| `cookies` | Every `Set-Cookie` on the page | Missing `Secure`/`HttpOnly`/`SameSite`, `SameSite=None` without `Secure` |
| `cors` | `Access-Control-Allow-*` with a probe `Origin` | Reflected origin (with or without credentials), `null` origin, wildcard + credentials |
| `tls` | Real handshake on the HTTPS port | Untrusted/self-signed/expired certificate, expiry inside 30 days, TLS 1.0/1.1 accepted, RC4/3DES/DES/NULL suites, sub-112-bit ciphers |
| `transport` | Whether HTTPS is actually enforced | Plaintext HTTP serving content, HTTPS reachable but HTTP not redirected, no TLS listener at all |
| `paths` | Ten commonly exposed files, with soft-404 suppression | `/.git/HEAD`, `/.env`, `.htaccess`, `package.json`, `/server-status`, `phpinfo.php`, `/actuator/env`, `.DS_Store`, `/backup.zip`, `/.svn/wc.db` |
| `methods` | `OPTIONS`/`TRACE` | `PUT`/`DELETE`/`TRACE`/`CONNECT`/`PATCH` advertised, TRACE echoing the request |
| `disclosure` | Banners, listings, errors, robots.txt | Version in `Server`/`X-Powered-By`, directory listing, stack traces / SQL errors on a non-existent path, `robots.txt` pointing at admin/backup paths |

Every finding carries a severity (`info`, `low`, `medium`, `high`, `critical`),
the URL, the evidence that produced it, a remediation and references.

Path probes use content signatures rather than status codes, and a random-path
baseline, so single-page apps that answer `200` to everything do not produce
false positives. Redirects are followed manually (up to 8 hops) and findings are
attributed to the URL that actually served the content.

## Reports

* **Terminal** — colourised when stdout is a TTY, grouped by severity, with a
  per-severity summary.
* **JSON** — schema-stable, machine readable:

  ```json
  {
    "tool": "vulnhunter",
    "version": "1.0.0",
    "target": "https://example.test/",
    "final_url": "https://example.test/",
    "status": 200,
    "redirects": 0,
    "started_at": "2026-10-25T20:22:54Z",
    "duration_seconds": 0.104,
    "summary": {"critical": 0, "high": 1, "medium": 4, "low": 3, "info": 1},
    "checks_run": ["headers", "cookies", "cors", "tls", "transport", "paths", "methods", "disclosure"],
    "errors": [],
    "findings": [{"check": "tls", "title": "...", "severity": "high", "description": "...",
                  "evidence": "...", "remediation": "...", "references": ["..."], "url": "..."}]
  }
  ```

* **HTML** — one file, no external assets, safe to attach to a ticket. All
  scanned content is HTML-escaped (covered by tests).
* **SARIF 2.1.0** — validated against the official schema, ready for GitHub code
  scanning and other SARIF consumers. Rule ids are stable across runs
  (`VH-<CHECK>-<TITLE>`), dynamic parts such as cookie names are stripped so one
  rule covers every affected cookie, and each result carries a deterministic
  `partialFingerprints` entry so alerts keep their identity between runs.
  Severities map to `error` (critical/high), `warning` (medium) and `note`
  (low/info), with GitHub `security-severity` scores of 9.5 / 8.0 / 5.5 / 3.0.

  By default each result carries the scanned URL as its location. That is valid
  SARIF, but GitHub code scanning only **displays** a result when its location is
  a repository-relative path for a file in the scanned commit, so pass
  `--sarif-location` to attach the findings to a committed file (the workflow
  file, an infrastructure config, or whatever genuinely defines the target).

### GitHub code scanning

[.github/workflows/vulnhunter.yml](.github/workflows/vulnhunter.yml) is included and does two things:

* **Tests** run on every push to `main` and every pull request, on Python 3.8 and
  3.12.
* **Scan** runs weekly (Mondays 06:00 UTC) and on manual dispatch. It scans every
  target listed in the `SCAN_TARGETS` repository variable, one matrix job per
  target, uploading each result under its own code scanning category and keeping
  each target's JSON/HTML/SARIF reports as its own build artifact. With no target
  configured it emits a warning and skips instead of failing.

### Configuring targets

`SCAN_TARGETS` is a repository *variable* (Settings → Secrets and variables →
Actions → Variables) holding every URL to scan. Either format works:

```text
["https://staging.example.com", "https://api.example.com/v1"]
```

```text
https://staging.example.com, https://api.example.com/v1
```

(A newline-separated list also works, and duplicates are scanned once.) The old
single-target `STAGING_URL` variable is still honoured when `SCAN_TARGETS` is
empty, and the `target` input on `workflow_dispatch` overrides both for a one-off
scan. Invalid entries — a JSON syntax error, or anything that is not an http(s)
URL — fail the resolve job with an explanatory annotation rather than being
silently skipped.

Each target's code scanning category is `vulnhunter/<slug>`, where the slug comes
from the host and path: `https://api.example.com/v1` becomes
`vulnhunter/api-example-com-v1`. That is stable across runs and distinct per host,
which is what lets several targets report into the same repository without their
alerts overwriting each other. Removing a target from the variable stops it being
scanned but leaves its previous alerts in place — dismiss them in code scanning if
you retire a target.

Prerequisites: code scanning must be enabled for the repository (public
repositories, or private/internal ones with GitHub Code Security), and the scan
job needs `security-events: write` — already set in the workflow. The relevant
steps are:

```yaml
permissions:
  contents: read
  security-events: write # required to upload SARIF to code scanning

strategy:
  fail-fast: false # one unreachable target must not cancel the others
  matrix: ${{ fromJSON(needs.targets.outputs.matrix) }}

- name: Run scan
  run: |
    python vulnhunter.py "${TARGET}" \
      --authorized --no-color --delay 0.2 \
      --sarif "${SLUG}.sarif" \
      --json "${SLUG}.json" \
      --html "${SLUG}.html" \
      --sarif-location .github/workflows/vulnhunter.yml

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ${{ matrix.slug }}.sarif
    category: vulnhunter/${{ matrix.slug }}
```

Keep each upload `category` fixed so repeated scans update the same alerts instead
of creating new ones — deriving it from the target makes that automatic — and
point `--sarif-location` at a file that exists in the commit you analyse: code
scanning will not display results whose location does not resolve to a committed
file. If you have no truthful file to point at, leave `--sarif-location` out: the
SARIF is still valid and uploadable, it just will not be shown as file-level
alerts.

Since the scan hits a live system, the workflow uses `--authorized` on your
behalf: only configure a target you are allowed to test.

## Limitations

Vulnhunter is a fast first pass, not a full pentest:

* No authentication, crawling beyond the entry page, fuzzing or exploitation.
* Heuristic: findings need verification in context. Missing `Permissions-Policy`
  is reported as `info` on purpose.
* It does not test business logic, access control between users, SSRF, or
  anything that requires a valid session. Bring Burp/ZAP and a human for that.
* Ten well-known paths only — it will not find a custom `/.git-backup-2019/`.
* Sequential requests with a default 100 ms delay; the whole scan is roughly
  20 requests.

## Tests

The suite is offline (a local fixture `http.server`) and covers each check, the
soft-404 suppression, TLS evaluation rules, report escaping, the authorization
gate and the CLI end to end:

```bash
python3 -m unittest discover -s tests -v
```

49 tests, no network access. The GitHub Actions workflow is additionally checked
with `actionlint` (including `shellcheck` on its run scripts), and its scan step
is reproducible locally against the fixture server.
