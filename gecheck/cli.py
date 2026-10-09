import argparse
import sys
from pathlib import Path

from . import RULES_VERSION, __version__
from .i18n import LANGS
from .model import SEV_RANK, SEVERITIES

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 3


def cmd_install(args):
    from .install import install
    print("GoldenEye Check: installing engines")
    install(force=args.force)
    return EXIT_OK


def cmd_scan(args):
    from .report import write_reports
    from .scanner import Options, run

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Folder not found: {root}", file=sys.stderr)
        return EXIT_ERROR
    lang = args.lang
    print(f"GoldenEye Check {__version__} · {root}")
    result = run(root, Options(history=not args.no_history, deps=not args.no_deps, offline=args.offline))

    out_dir = Path(args.out).resolve() if args.out else root / ".goldeneye-check"
    formats = {f.strip() for f in args.format.split(",") if f.strip()}
    written = write_reports(result, out_dir, formats, lang, include_snippets=args.include_snippets)

    return _summary(result, written, args.fail_on)


YES = {"yes", "y"}
CONFIRM = ("You may only check your own site or a site whose owner has agreed.\n"
           "Does {host} belong to you? (yes/no): ")


def _summary(result, written, fail_on):
    c = result.counts
    print()
    print(f"Security score: {result.score}/100, grade {result.grade}")
    print(f"Total findings: {len(result.findings)} ("
          + ", ".join(f"{s}: {c[s]}" for s in SEVERITIES) + ")")
    for w in result.warnings:
        print(f"! {w}")
    for p in written:
        print(f"→ {p}")
    if fail_on == "none":
        return EXIT_OK
    limit = SEV_RANK[fail_on]
    return EXIT_FINDINGS if any(SEV_RANK[f.severity] <= limit for f in result.findings) else EXIT_OK


def cmd_site(args):
    from .report import write_reports
    from .site import normalize, run_site

    try:
        base, host, _ = normalize(args.url)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return EXIT_ERROR
    if not args.yes_i_own_this:
        if not sys.stdin.isatty():
            print("Confirm that the site is yours: add --yes-i-own-this", file=sys.stderr)
            return EXIT_ERROR
        try:
            answer = input(CONFIRM.format(host=host)).strip().lower()
        except EOFError:  # no stdin, treat as a refusal
            answer = ""
        if answer not in YES:
            print("Cancelled.")
            return EXIT_ERROR
    print(f"GoldenEye Check {__version__} · {base}")
    result = run_site(base)
    out_dir = Path(args.out).resolve() if args.out else Path.cwd() / ".goldeneye-check" / host
    formats = {f.strip() for f in args.format.split(",") if f.strip()}
    written = write_reports(result, out_dir, formats, args.lang)
    return _summary(result, written, args.fail_on)


def cmd_rules(args):
    from .paths import RULES_DIR

    for f in sorted(RULES_DIR.glob("*.yaml")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("- id: ge."):
                print(line.split("id:", 1)[1].strip())
    print(f"rules {RULES_VERSION} + built-in configuration checks (ge.config.*)")
    return EXIT_OK


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="gecheck", description="GoldenEye Check: checks code and websites for vulnerabilities")
    ap.add_argument("--version", action="version", version=f"GoldenEye Check {__version__} (rules {RULES_VERSION})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("install", help="download the engines (gitleaks, osv-scanner, opengrep)")
    p.add_argument("--force", action="store_true", help="reinstall even if already installed")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("scan", help="check a project")
    p.add_argument("path", nargs="?", default=".", help="project folder (default: current folder)")
    p.add_argument("--lang", choices=LANGS, default="en", help="report language")
    p.add_argument("--out", help="where to save reports (default: <project>/.goldeneye-check)")
    p.add_argument("--format", default="html,md,json", help="html, md, json, comma-separated")
    p.add_argument("--no-history", action="store_true", help="do not search git history for secrets")
    p.add_argument("--no-deps", action="store_true", help="do not check dependencies")
    p.add_argument("--offline", action="store_true", help="check dependencies without network access")
    p.add_argument("--include-snippets", action="store_true", help="include code snippets in report.json")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="critical",
                   help="exit code 1 if there are findings of this severity or above (for CI)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("site", help="check a published website (your own only)")
    p.add_argument("url", help="site address, for example example.com")
    p.add_argument("--lang", choices=LANGS, default="en", help="report language")
    p.add_argument("--out", help="where to save reports (default: ./.goldeneye-check/<site>)")
    p.add_argument("--format", default="html,md,json", help="html, md, json, comma-separated")
    p.add_argument("--yes-i-own-this", action="store_true", help="confirm that the site is yours without a prompt")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="critical",
                   help="exit code 1 if there are findings of this severity or above")
    p.set_defaults(func=cmd_site)

    p = sub.add_parser("rules", help="list GoldenEye rules")
    p.set_defaults(func=cmd_rules)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
