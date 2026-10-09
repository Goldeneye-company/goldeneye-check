# GoldenEye Check

A free tool that checks code and websites for common vulnerabilities.
It is made for people who write code themselves or together with AI (Cursor, Claude, Lovable, Bolt, v0) and want to ship a project without security holes.

The check runs on your computer. Your source code is not sent anywhere. Reports are available in English, Russian and Kazakh.

## Installation

You need [Python](https://www.python.org/downloads/) 3.9 or newer. On Windows, select "Add python.exe to PATH" when installing Python.

```bash
pip install https://github.com/Goldeneye-company/goldeneye-check/archive/refs/heads/main.zip
```

```bash
gecheck install
```

The second command downloads the scanning engines (about 135 MB) to `~/.goldeneye-check/engines`. You can choose another folder with the `GECHECK_HOME` environment variable. Supported platforms: Windows x64, Linux x64 and macOS on Apple Silicon.

If the system says the `gecheck` command is not found, the Scripts folder of your Python is not in PATH. In that case run the program through Python: `python -m gecheck install`, `python -m gecheck scan .` and so on. pip shows the path to this folder in a warning during installation.

## Usage

Check the project in the current folder:

```bash
gecheck scan .
```

Check your own published website:

```bash
gecheck site example.com
```

Reports are saved to the `.goldeneye-check` folder inside the project: `report.html`, `report.md` and `report.json`.
Examples: [English](examples/report-en.html), [Russian](examples/report-ru.html), [Kazakh](examples/report-kk.html).

`gecheck scan` options:

| Option | Purpose |
|---|---|
| `--lang ru`, `--lang kk` | report language (English by default) |
| `--out folder` | where to save the reports |
| `--format json` | report formats: `html`, `md`, `json`, comma-separated |
| `--no-history` | do not search git history for secrets |
| `--offline` | check dependencies without network access |
| `--fail-on high` | exit with code 1 if there are findings of high severity or above |

## What is checked

`gecheck scan`:

- secrets in files and in git history (gitleaks): OpenAI, Anthropic, Stripe, AWS, GitHub, Telegram and other service keys. Values are masked in the report;
- vulnerable dependencies from npm, pip, composer, go and other lock files (osv-scanner). Only package names and versions are sent to the OSV database;
- vulnerabilities in JavaScript, TypeScript, Python and PHP code (opengrep and our own rules): SQL and NoSQL injection, XSS, command injection, SSRF, path traversal, eval, unsafe deserialization, JWT without signature verification, hardcoded passwords;
- calls to paid AI APIs without authorization or without a `max_tokens` limit;
- configuration: `.env` committed to the repository, secrets in `NEXT_PUBLIC_` and `VITE_` variables, Supabase tables without RLS, open Firebase rules, default passwords and exposed database ports in docker-compose, directory listing in `.htaccess`.

`gecheck rules` prints the full list of rules.

`gecheck site` checks HTTPS and the redirect to it, certificate expiry, security headers, cookie flags, server version in headers, service files reachable from outside (`.env`, `.git`, database dumps, `phpinfo.php`, archives) and open directory listings. The program sends about 30 ordinary GET requests and asks you to confirm that the site is yours before it starts. Only check your own sites or sites whose owner has agreed to it.

Things the program cannot check (spending limits, two-factor authentication, backups and so on) are listed in [CHECKLIST.md](CHECKLIST.md).

## Score

The score starts at 100. Each critical finding subtracts 25, high 10, medium 4, low 1. Vulnerable dependencies lower the score by 30 at most. Grade A is 90 and above, B is 75 and above, C is below 75 or any high finding, D is below 50 or any critical finding, F is below 25.

## GitHub Actions

```yaml
- run: pip install https://github.com/Goldeneye-company/goldeneye-check/archive/refs/heads/main.zip && gecheck install
- run: gecheck scan . --fail-on critical --format md,json
```

## Accuracy

`bench/` contains a generator for a test project with 29 vulnerabilities and 9 safe code samples. The current version finds all 29 with no false positives. Run it with `python bench/benchmark.py`.

Results on open projects (OWASP NodeGoat, DVWA, PyGoat, nextjs/saas-starter, fastapi/full-stack-fastapi-template) are in [bench/REALRUN.md](bench/REALRUN.md): 67 of 72 findings were correct.

## Limitations

The program looks for common mistakes. It does not check access control logic, session handling, cloud or payment settings, and it does not tell whether the vulnerable code of a dependency is actually used in your project. No findings does not mean no vulnerabilities.

You can order a manual review from us: https://goldeneye.kz/en/audit/

## Development

```bash
python -m unittest discover -s tests
python bench/benchmark.py
```

Rules are in `gecheck/rules/`. How to add a new one is described in [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in the program itself, use the address in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0, see [LICENSE](LICENSE). Licenses of the third-party engines are listed in [NOTICE](NOTICE).

© 2026 GOLDENEYE LLP
