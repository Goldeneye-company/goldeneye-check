# Changelog

## Unreleased

- SARIF 2.1.0 report (`--format sarif`) for GitHub code scanning, DefectDojo and other tools.
- gecheck site: on Windows, trusted root certificates that the system has not downloaded yet no longer cause a false "certificate is invalid" finding.
- gecheck site: new finding when the server does not send its intermediate certificate (Python 3.13 or newer).
- The HTML report opens in the browser after `gecheck scan` and `gecheck site` (not in CI or scripts). `--no-open` turns it off.
- `gecheck install` says what to run next. When the short `gecheck` command is not in PATH (the default with the Python install manager on Windows), the program suggests `python -m gecheck` in all its hints.
- README: step-by-step quick start without an IDE.
- Secrets: OpenAI keys that end with a hyphen are now found. The default gitleaks rule missed them (about 1 key in 64).
- Implicit configuration: a knowledge base of image defaults (`gecheck/kb/defaults.json`) for php, Apache, nginx, PostgreSQL, MySQL, node and python images. The scanner combines it with the files the Dockerfile copies into the configuration folders and finds settings that nobody set: PHP showing errors to users, no session strict mode, no time zone, the application using the PostgreSQL superuser, server version in headers.
- Java and Go: the knowledge base covers JDK images, maven, gradle, Tomcat, golang and distroless images, Spring Boot and Gin. New findings: a build image (golang, maven, gradle) used for the running container, the JDWP debugger or JMX without authentication turned on, Tomcat default applications copied back, Spring Boot actuator endpoints exposed, the H2 console on, stack traces in error responses, Gin in debug mode, net/http/pprof in production code, Go HTTP servers without timeouts.
- docker-compose and Dockerfile checks: secrets with a default value (`${VAR:-value}`), the application published over plain HTTP without a TLS proxy, containers without `read_only`, `cap_drop`, `no-new-privileges`, resource limits or a non-root user, images not pinned by digest.
- Code checks: secrets that fall back to a literal when the environment variable is missing (PHP, JavaScript, Python), a default password printed on a page, session cookies without the Secure flag.
- Findings of the new checks carry the detector type, category A-O, ISO/IEC 27002:2022 controls, confidence, effort and the readiness stage of the fix (JSON report).
- Reference project test (`tests/test_corpus.py`): a real PHP application with 27 known problems, and its fixed version, where the scanner must find nothing beyond what the project documents as left open.
- Missing measures: sign-in without an attempt limit (critical without a second factor), response time that reveals existing accounts, uploads stored without an antivirus check, integrity hash or encryption, uploaded data that is never deleted, no upload quota, databases without backups, attempt limits checked without a lock, generated passwords and tokens with too little entropy, no global exception handler in plain PHP, password hashing or CREATE TABLE in a bootstrap file that runs on every request (PHP, with sign-in and upload checks for JavaScript and Python).
- Confirmed measures: the JSON report lists the security measures found in the code with file and lines (prepared statements, output escaping, CSRF checks, session id renewal, security headers and others). The checks use them as evidence: a measure found nearby removes or lowers a finding.
- File inventory: the JSON report lists entry points, configuration and secret files and what the project lacks (tests, CI, migrations, web server configuration, lock files). Scanner reports, database dumps and logs with internal IP addresses that `.gitignore` does not exclude are reported.
- Routes: the scanner finds the entry points of PHP front controllers, route tables and endpoint files, Express, Flask, FastAPI, Django, Spring and Go (net/http, gin) and builds the "route x measure" matrix: sign-in required, data changed, CSRF check, owner check, audit log entry, Cache-Control: no-store. Findings: user actions without an audit entry, responses with passwords or files that may be cached, objects taken by an id without an owner check, data changes without a CSRF check, sign-out by GET, secret tokens in the query string while the web server logs it, links built from the Host header, secrets kept in the session, sessions without timeouts, no Content-Security-Policy, ids that raise an unhandled exception when the object does not exist, accounts without a password change or disabling.
- System model: the JSON report describes assets (tables with passwords, documents, logs), subjects, entry points with the matrix, and trust boundaries.
- Java and Go: rules for SQL and command injection, path traversal, SSRF, XSS, open redirects, Java deserialization, XXE, Spring Security with CSRF turned off or every request allowed, passwords without a slow hash, Go TLS without certificate verification.
- The reference test now enforces the methodology criteria on every commit.
- Report in the order of a security review: readiness verdict and the three problems to fix first, confirmed measures with lines, the README statements with their status (implemented, implemented with flaws, not implemented), findings with category, ISO/IEC 27002:2022 controls, readiness stage and effort, a short ISO/IEC 27001 Annex A summary, a roadmap by readiness stage, the routes table, coverage and limitations. HTML and Markdown in three languages; JSON and SARIF carry the same fields.
- Coverage: the share of categories A-O checked for the project's languages. Grade A needs 80% coverage; below 60% the score is marked preliminary.
- The README is read for the purpose of the system, stated measures and admitted limitations. A stated measure that the code does not have is a finding; problems the README admits are marked as known; a planned reverse proxy is noted next to limits counted per IP.
- Findings that make a worse attack together are linked (a default password and a sign-in without an attempt limit).
- Findings of opengrep, gitleaks, osv-scanner and the built-in checks get a category, ISO controls and a readiness stage too.
- Pro AI review (`--ai`): Claude, called with the customer's own Anthropic key, reviews the route handlers for access logic, information shown before authentication, secrets delivered together with what they protect, races and unenforced business rules, and reads security statements in the README. Answers must point to a sent line and quote it; duplicates of static findings are dropped; model-only findings are at most medium confidence. `--ai-dry-run` writes what would be sent. Optional dependency: `pip install "goldeneye-check[ai]"` (Python 3.10+).
- Routes: data files that mention `Cache-Control: no-store` no longer count as setting it.
- Pro: the server sends compliance tables with the Pro rules. The report then shows every ISO/IEC 27002:2022 control with its status, the lines that support it and the findings against it, the requirements of Kazakhstan with their status, and a self-assessment checklist of organisational controls. `report-audit.html` is a report for management and auditors; `--format pdf` prints it to `report-audit.pdf` with an installed Edge, Chrome or Chromium. The JSON report carries the statuses and references, not the texts of the tables.
- The `.goldeneye-check` folder now gets its own `.gitignore`, so reports are not committed by mistake.
- PHP: the XSS rule accepts the common escaping helpers `e()`, `h()`, `esc()` and WordPress `esc_html()`, `esc_attr()`, `esc_url()`; ini files copied to `$PHP_INI_DIR/conf.d/` are taken into account.

## 0.1.0 (October 21, 2026)

First release.

- `gecheck scan`: secrets in files and git history (gitleaks), dependency check (osv-scanner), code analysis for JavaScript, TypeScript, Python and PHP (opengrep), configuration checks for Supabase, Firebase, docker-compose, `.env` and `.htaccess`.
- `gecheck site`: HTTPS, certificate, security headers, cookies, exposed service files and directory listings.
- Reports in HTML, Markdown and JSON in English, Russian and Kazakh. English is the default.
- Security score and grade from A to F, `--fail-on` option for CI.
- Pro: `gecheck login`, `gecheck logout`, `gecheck balance`, and `gecheck scan --pro` / `--no-pro`. After login, `gecheck scan` offers to add the Pro rules from the goldeneye.kz server.
- The installer retries engine downloads on server errors.
