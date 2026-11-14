# Changelog

## Unreleased

- SARIF 2.1.0 report (`--format sarif`) for GitHub code scanning, DefectDojo and other tools.
- gecheck site: on Windows, trusted root certificates that the system has not downloaded yet no longer cause a false "certificate is invalid" finding.
- gecheck site: new finding when the server does not send its intermediate certificate (Python 3.13 or newer).
- The HTML report opens in the browser after `gecheck scan` and `gecheck site` (not in CI or scripts). `--no-open` turns it off.
- `gecheck install` says what to run next. When the short `gecheck` command is not in PATH (the default with the Python install manager on Windows), the program suggests `python -m gecheck` in all its hints.
- README: step-by-step quick start without an IDE.
- Secrets: OpenAI keys that end with a hyphen are now found. The default gitleaks rule missed them (about 1 key in 64).

## 0.1.0 (October 21, 2026)

First release.

- `gecheck scan`: secrets in files and git history (gitleaks), dependency check (osv-scanner), code analysis for JavaScript, TypeScript, Python and PHP (opengrep), configuration checks for Supabase, Firebase, docker-compose, `.env` and `.htaccess`.
- `gecheck site`: HTTPS, certificate, security headers, cookies, exposed service files and directory listings.
- Reports in HTML, Markdown and JSON in English, Russian and Kazakh. English is the default.
- Security score and grade from A to F, `--fail-on` option for CI.
- Pro: `gecheck login`, `gecheck logout`, `gecheck balance`, and `gecheck scan --pro` / `--no-pro`. After login, `gecheck scan` offers to add the Pro rules from the goldeneye.kz server.
- The installer retries engine downloads on server errors.
