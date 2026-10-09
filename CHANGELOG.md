# Changelog

## 0.1.0 (October 9, 2026)

First release.

- `gecheck scan`: secrets in files and git history (gitleaks), dependency check (osv-scanner), code analysis for JavaScript, TypeScript, Python and PHP (opengrep), configuration checks for Supabase, Firebase, docker-compose, `.env` and `.htaccess`.
- `gecheck site`: HTTPS, certificate, security headers, cookies, exposed service files and directory listings.
- Reports in HTML, Markdown and JSON in Kazakh, Russian and English.
- Security score and grade from A to F, `--fail-on` option for CI.
- The installer retries engine downloads on server errors.
