# Changelog

## 0.1.0 (October 21, 2026)

First release.

- `gecheck scan`: secrets in files and git history (gitleaks), dependency check (osv-scanner), code analysis for JavaScript, TypeScript, Python and PHP (opengrep), configuration checks for Supabase, Firebase, docker-compose, `.env` and `.htaccess`.
- `gecheck site`: HTTPS, certificate, security headers, cookies, exposed service files and directory listings.
- Reports in HTML, Markdown and JSON in English, Russian and Kazakh. English is the default.
- Security score and grade from A to F, `--fail-on` option for CI.
- Pro: `gecheck login`, `gecheck logout`, `gecheck balance`, and `gecheck scan --pro` / `--no-pro`. After login, `gecheck scan` offers to add the Pro rules from the goldeneye.kz server.
- The installer retries engine downloads on server errors.
