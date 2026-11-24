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
- Reference project test (`tests/test_corpus.py`): a real PHP application with 27 known problems.

## 0.1.0 (October 21, 2026)

First release.

- `gecheck scan`: secrets in files and git history (gitleaks), dependency check (osv-scanner), code analysis for JavaScript, TypeScript, Python and PHP (opengrep), configuration checks for Supabase, Firebase, docker-compose, `.env` and `.htaccess`.
- `gecheck site`: HTTPS, certificate, security headers, cookies, exposed service files and directory listings.
- Reports in HTML, Markdown and JSON in English, Russian and Kazakh. English is the default.
- Security score and grade from A to F, `--fail-on` option for CI.
- Pro: `gecheck login`, `gecheck logout`, `gecheck balance`, and `gecheck scan --pro` / `--no-pro`. After login, `gecheck scan` offers to add the Pro rules from the goldeneye.kz server.
- The installer retries engine downloads on server errors.
