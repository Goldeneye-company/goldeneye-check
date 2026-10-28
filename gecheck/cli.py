import argparse
import os
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
    import shutil

    from .i18n import UI, tri
    from .report import write_reports
    from .scanner import Options, run

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Folder not found: {root}", file=sys.stderr)
        return EXIT_ERROR
    print(f"GoldenEye Check {__version__} · {root}")

    pro_dir, pro_res = None, None
    if not args.no_pro:
        pro_dir, pro_res = _pro_rules(root, forced=args.pro)
        if pro_dir is False:
            return EXIT_ERROR
    options = Options(history=not args.no_history, deps=not args.no_deps, offline=args.offline,
                      pro_rules=pro_dir, pro_version=(pro_res or {}).get("version", ""))
    try:
        result = run(root, options)
    finally:
        if pro_dir:
            shutil.rmtree(pro_dir, ignore_errors=True)
    if pro_res:
        until = (pro_res.get("free_until") or "")[:10]
        key = "pro_used_charged" if pro_res.get("charged") else "pro_used_free"
        result.notice = tri(UI[key], balance=pro_res.get("balance", 0), until=until)

    out_dir = Path(args.out).resolve() if args.out else root / ".goldeneye-check"
    formats = {f.strip() for f in args.format.split(",") if f.strip()}
    written = write_reports(result, out_dir, formats, args.lang, include_snippets=args.include_snippets)

    return _summary(result, written, args.fail_on)


def _pro_rules(root, forced):
    """Asks whether to add the Pro rules and downloads them.

    Returns (folder, server response), (None, None) to scan without Pro,
    or (False, None) if --pro was given but Pro cannot be used.
    """
    from . import pro
    from .install import engine_path
    from .scanner import project_id

    skip = (False, None) if forced else (None, None)
    tok = pro.token()
    if not tok:
        if forced:
            print("To use Pro, log in first: gecheck login", file=sys.stderr)
        return skip
    if not forced and not _interactive():
        print("Pro rules are not used. Add --pro to use them when running from a script.")
        return skip
    if not engine_path("opengrep").exists():
        print("Pro needs the engines. Run gecheck install first.", file=sys.stderr)
        return skip
    pid = project_id(root)
    try:
        q = pro.quote(tok, pid)
    except pro.ApiError as e:
        print(f"Pro: {pro.explain(e)}", file=sys.stderr)
        return skip
    if q.get("free_until"):
        offer = f"The Pro check of this project is free until {q['free_until'][:10]}."
    elif q.get("balance", 0) > 0:
        offer = f"The Pro check uses 1 check from your package ({q['balance']} left)."
    else:
        print(f"No Pro checks left in your package. Packages: {pro.BUY_URL}")
        return skip
    if forced:
        print(offer)
    else:
        try:
            answer = input(f"{offer} Run it? (yes/no): ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in YES:
            return None, None
    try:
        folder, res = pro.fetch_rules(tok, pid)
    except pro.ApiError as e:
        print(f"Pro: {pro.explain(e)}", file=sys.stderr)
        return skip
    if res.get("charged"):
        print(f"1 check used, {res.get('balance', 0)} left.")
    else:
        print("No check used: this is a free re-check.")
    return folder, res


def cmd_login(args):
    import re

    from . import pro
    email = (args.email or input("Email: ")).strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        print("This does not look like an email address.", file=sys.stderr)
        return EXIT_ERROR
    try:
        pro.call("login.php", {"email": email})
        print(f"A code has been sent to {email}. It is valid for 15 minutes.")
        code = (args.code or input("Code from the email: ")).strip()
        res = pro.call("verify.php", {"email": email, "code": code})
    except pro.ApiError as e:
        print(pro.explain(e), file=sys.stderr)
        return EXIT_ERROR
    pro.save_state({"email": email, "token": res["token"]})
    print(f"Logged in. Pro checks left: {res.get('balance', 0)}")
    return EXIT_OK


def cmd_logout(args):
    from . import pro
    pro.save_state({})
    print("Logged out.")
    return EXIT_OK


def cmd_balance(args):
    from . import pro
    tok = pro.token()
    if not tok:
        print(f"Not logged in. To use Pro, buy a package ({pro.BUY_URL}) and run gecheck login")
        return EXIT_ERROR
    try:
        res = pro.call("balance.php", token=tok)
    except pro.ApiError as e:
        print(pro.explain(e), file=sys.stderr)
        return EXIT_ERROR
    print(f"{pro.load_state().get('email', 'Account')}: {res['balance']} Pro checks left")
    for p in res.get("packages", []):
        print(f"  package of {p['total']}: {p['used']} used, valid until {p['expires_at'][:10]}")
    if not res["balance"]:
        print(f"Packages: {pro.BUY_URL}")
    return EXIT_OK


YES = {"yes", "y"}


def _interactive() -> bool:
    """A person can answer questions. On Windows the NUL device also reports isatty(), so check the console."""
    if not sys.stdin or not sys.stdin.isatty():
        return False
    if os.name == "nt":
        import ctypes
        import msvcrt
        mode = ctypes.c_uint32()
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    return True
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
        if not _interactive():
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
    p.add_argument("--format", default="html,md,json", help="html, md, json, sarif, comma-separated")
    p.add_argument("--no-history", action="store_true", help="do not search git history for secrets")
    p.add_argument("--no-deps", action="store_true", help="do not check dependencies")
    p.add_argument("--offline", action="store_true", help="check dependencies without network access")
    p.add_argument("--include-snippets", action="store_true", help="include code snippets in report.json")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="critical",
                   help="exit code 1 if there are findings of this severity or above (for CI)")
    pro_mode = p.add_mutually_exclusive_group()
    pro_mode.add_argument("--pro", action="store_true", help="add the Pro rules without asking (uses 1 check)")
    pro_mode.add_argument("--no-pro", action="store_true", help="do not offer the Pro rules")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("site", help="check a published website (your own only)")
    p.add_argument("url", help="site address, for example example.com")
    p.add_argument("--lang", choices=LANGS, default="en", help="report language")
    p.add_argument("--out", help="where to save reports (default: ./.goldeneye-check/<site>)")
    p.add_argument("--format", default="html,md,json", help="html, md, json, sarif, comma-separated")
    p.add_argument("--yes-i-own-this", action="store_true", help="confirm that the site is yours without a prompt")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="critical",
                   help="exit code 1 if there are findings of this severity or above")
    p.set_defaults(func=cmd_site)

    p = sub.add_parser("rules", help="list GoldenEye rules")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("login", help="log in to use Pro (a code is sent by email)")
    p.add_argument("email", nargs="?")
    p.add_argument("--code", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_login)

    sub.add_parser("logout", help="log out").set_defaults(func=cmd_logout)
    sub.add_parser("balance", help="show how many Pro checks are left").set_defaults(func=cmd_balance)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
