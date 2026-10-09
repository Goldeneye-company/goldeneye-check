# Results on open projects

Date: October 4, 2026. Version: GoldenEye Check 0.1.0, rules 2026.10.0.

Findings in code, secrets and configuration were verified by hand against the source code. Dependency findings were not verified by hand; they come from the OSV database.

## Projects

| Project | Description |
|---|---|
| OWASP NodeGoat | intentionally vulnerable Express application |
| DVWA | intentionally vulnerable PHP application |
| PyGoat | intentionally vulnerable Django and Flask application |
| nextjs/saas-starter | SaaS template on Next.js and Stripe |
| fastapi/full-stack-fastapi-template | application template on FastAPI and React |

## Results

| Project | Score | Findings (code, secrets, configuration) | False | Dependencies | Time |
|---|---|---|---|---|---|
| NodeGoat | 0, F | 14 | 0 | 130 | 7 s |
| DVWA | 0, F | 18 | 4 | 0 | 4 s |
| PyGoat | 0, F | 33 | 0* | 26 | 19 s |
| saas-starter | 61, C | 3 (medium and low) | 0 | 11 | 5 s |
| full-stack-fastapi-template | 60, C | 4 (medium and low) | 1 | 12 | 8 s |

67 of 72 findings are correct, about 93%.

\* In PyGoat, 10 of 33 findings were checked by hand; the rest are of the same kind.

False positives:

- DVWA, `recaptchalib.php:41` and `csrf/help/help.php:54`: gitleaks took an HTML fragment and a sample request from the help page for a key.
- DVWA, `check_token_high.php:24` and `check_token_impossible.php:24`: output of a JSON response was reported as XSS.
- fastapi-template: a sample `SECRET_KEY` from the template's README in git history.

## What was found

- NodeGoat: eval on form data (3 places), NoSQL injection through `$where`, disabled template autoescaping, SSRF, open redirect, a private TLS key in the repository and in history, a ZAP key in configuration, passwords in a seed script, 130 vulnerable packages.
- DVWA: command injection (low, medium, high levels and API), SQL injection (sqli, blind, brute, authbypass), JSONP injection, an SQLite database file in the repository. No findings at the impossible level.
- PyGoat: pickle and `yaml.load` on user data, eval, `shell=True`, `SECRET_KEY` in code, `DEBUG = True`, Stripe keys and passwords in git history.
- saas-starter: a Stripe test key and webhook secret that were added to the README in September 2024 and removed later, but remain in git history. A password in a seed script (low).
- fastapi-template: a `.env` file with `changethis` placeholders is stored in git (medium), the database port is exposed in `compose.override.yml` (low).

## What was not found

| Class | Example | Reason |
|---|---|---|
| Access control | IDOR in NodeGoat (allocations by userId), BAC in DVWA | requires understanding the business logic |
| Authentication and sessions | weak passwords, session settings in NodeGoat, CSRF | depends on framework settings |
| Data flow across files | xss_r, xss_s, fi in DVWA | rules work within a single file |
| Use of vulnerable dependency functions | a Next.js vulnerability in a static site | reachability analysis is not performed |

## Changes after the run

1. RLS is checked only in Supabase projects. Before, the rule fired on Drizzle migrations.
2. The severity of ".env in git" depends on the contents: critical for values that look real, medium for placeholders, low if there are no secrets.
3. Secrets in documentation and tests, and Stripe test keys, get medium. The heuristic gitleaks rule generic-api-key gets high; recognized service keys get critical.
4. Passwords in seed scripts and tests get low.
5. In PHP, a value after `is_numeric`, `preg_match`, `ctype_digit` and `filter_var` is treated as validated. This removed false positives at the impossible and BAC levels in DVWA.
6. Added rules for NoSQL `$where` and disabled template autoescaping.
7. The report masks only the secret value, not every quoted string.
8. A key removed from a file that is still in the repository is now reported as a git history finding. Duplicates for moved files were removed.
9. The penalty for vulnerable dependencies is capped at 30 points. For saas-starter and fastapi-template, the score changed from 0 (F) to 61 and 60 (C).

Each change is covered by a test or an example in the test project.
