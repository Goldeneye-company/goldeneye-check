import argparse
import sys
from pathlib import Path

from . import RULES_VERSION, __version__
from .i18n import LANGS, SEVERITY, UI, t
from .model import SEV_RANK, SEVERITIES

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 3


def cmd_install(args):
    from .install import install
    print("GoldenEye Check: установка движков")
    install(force=args.force)
    return EXIT_OK


def cmd_scan(args):
    from .report import write_reports
    from .scanner import Options, run

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Папка не найдена: {root}", file=sys.stderr)
        return EXIT_ERROR
    lang = args.lang
    print(f"GoldenEye Check {__version__} · {root}")
    result = run(root, Options(history=not args.no_history, deps=not args.no_deps, offline=args.offline))

    out_dir = Path(args.out).resolve() if args.out else root / ".goldeneye-check"
    formats = {f.strip() for f in args.format.split(",") if f.strip()}
    written = write_reports(result, out_dir, formats, lang, include_snippets=args.include_snippets)

    return _summary(result, written, lang, args.fail_on)


YES = {"да", "д", "yes", "y", "иә", "иа", "и"}


def _summary(result, written, lang, fail_on):
    c = result.counts
    print()
    print(f"{t(UI, 'score', lang)}: {result.score}/100 · {t(UI, 'grade', lang)} {result.grade}")
    print(f"{t(UI, 'total', lang)}: {len(result.findings)} — "
          + ", ".join(f"{t(SEVERITY, s, lang).lower()} {c[s]}" for s in SEVERITIES))
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
            print("Подтвердите, что сайт ваш: добавьте --yes-i-own-this", file=sys.stderr)
            return EXIT_ERROR
        try:
            answer = input(t(UI, "confirm_owner", args.lang, host=host)).strip().lower()
        except EOFError:  # нет stdin, считаем отказом
            answer = ""
        if answer not in YES:
            print("Отменено.")
            return EXIT_ERROR
    print(f"GoldenEye Check {__version__} · {base}")
    result = run_site(base)
    out_dir = Path(args.out).resolve() if args.out else Path.cwd() / ".goldeneye-check" / host
    formats = {f.strip() for f in args.format.split(",") if f.strip()}
    written = write_reports(result, out_dir, formats, args.lang)
    return _summary(result, written, args.lang, args.fail_on)


def cmd_rules(args):
    from .paths import RULES_DIR

    for f in sorted(RULES_DIR.glob("*.yaml")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("- id: ge."):
                print(line.split("id:", 1)[1].strip())
    print(f"rules {RULES_VERSION} + встроенные проверки конфигураций (ge.config.*)")
    return EXIT_OK


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="gecheck", description="GoldenEye Check — проверка кода на уязвимости")
    ap.add_argument("--version", action="version", version=f"GoldenEye Check {__version__} (rules {RULES_VERSION})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("install", help="скачать движки (gitleaks, osv-scanner, opengrep)")
    p.add_argument("--force", action="store_true", help="переустановить, даже если уже есть")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("scan", help="проверить проект")
    p.add_argument("path", nargs="?", default=".", help="папка проекта (по умолчанию текущая)")
    p.add_argument("--lang", choices=LANGS, default="ru", help="язык отчёта")
    p.add_argument("--out", help="куда сохранить отчёты (по умолчанию <проект>/.goldeneye-check)")
    p.add_argument("--format", default="html,md,json", help="html, md, json через запятую")
    p.add_argument("--no-history", action="store_true", help="не искать секреты в истории git")
    p.add_argument("--no-deps", action="store_true", help="не проверять зависимости")
    p.add_argument("--offline", action="store_true", help="проверять зависимости без обращения к сети")
    p.add_argument("--include-snippets", action="store_true", help="добавить фрагменты кода в report.json")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="critical",
                   help="код выхода 1, если есть находки этого уровня или выше (для CI)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("site", help="проверить опубликованный сайт (только свой)")
    p.add_argument("url", help="адрес сайта, например goldeneye.kz")
    p.add_argument("--lang", choices=LANGS, default="ru", help="язык отчёта")
    p.add_argument("--out", help="куда сохранить отчёты (по умолчанию ./.goldeneye-check/<сайт>)")
    p.add_argument("--format", default="html,md,json", help="html, md, json через запятую")
    p.add_argument("--yes-i-own-this", action="store_true", help="подтвердить, что сайт ваш, без вопроса")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="critical",
                   help="код выхода 1, если есть находки этого уровня или выше")
    p.set_defaults(func=cmd_site)

    p = sub.add_parser("rules", help="список правил GoldenEye")
    p.set_defaults(func=cmd_rules)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
