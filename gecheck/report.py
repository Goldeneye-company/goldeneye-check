"""Reports in HTML, Markdown and JSON."""

import html
import json
from pathlib import Path

from . import RULES_VERSION, __version__
from .i18n import CATEGORY, SEVERITY, UI, t
from .model import SEVERITIES

SCHEMA = "goldeneye-check/report@1"


def to_json(result, include_snippets=False) -> dict:
    """JSON without code snippets unless include_snippets is set."""
    findings = []
    for f in result.findings:
        if f.locked:
            findings.append({"fingerprint": f.fingerprint(), "severity": f.severity,
                             "category": f.category, "locked": True})
            continue
        item = {
            "fingerprint": f.fingerprint(), "rule": f.rule, "engine": f.engine,
            "severity": f.severity, "category": f.category, "cwe": f.cwe,
            "file": f.file, "line": f.line, "in_history": f.in_history, "commit": f.commit,
            "title": f.title, "fix": f.fix, "detail": f.detail or None,
        }
        if include_snippets and f.snippet:
            item["snippet"] = f.snippet
        findings.append(item)
    return {
        "schema": SCHEMA,
        "tool": {"name": "GoldenEye Check", "version": __version__, "rules": RULES_VERSION,
                 "engines": result.engines},
        "scan": {"started_at": result.started_at, "duration_s": result.duration,
                 "kind": result.kind,
                 "project": {"id": result.project_id, "name": result.root.name},
                 "git": {k: v for k, v in result.git.items() if k != "remote"},
                 "options": {"history": result.options.history, "deps": result.options.deps,
                             "offline": result.options.offline, "snippets": include_snippets}},
        "summary": {"score": result.score, "grade": result.grade, "total": len(result.findings),
                    "counts": result.counts},
        "warnings": result.warnings,
        "notice": result.notice,
        "findings": findings,
    }


def _where(f, lang):
    if f.locked:
        return t(UI, "locked_where", lang)
    loc = f.file + (f":{f.line}" if f.line else "")
    if f.in_history:
        loc += f" ({t(UI, 'in_history', lang)}{', ' + f.commit if f.commit else ''})"
    return loc


def _limits_key(result) -> str:
    if result.kind == "site":
        return "limits_site"
    return "limits_offline" if result.options.offline else "limits"


def _subject(result) -> str:
    return "site" if result.kind == "site" else "project"


def to_markdown(result, lang="en") -> str:
    c = result.counts
    sev = {s: t(SEVERITY, s, lang) for s in SEVERITIES}
    lines = [
        f"# GoldenEye Check: {t(UI, 'report_title_site' if result.kind == 'site' else 'report_title', lang).lower()}", "",
        f"**{t(UI, _subject(result), lang)}:** {result.root.name}  ",
        f"**{t(UI, 'date', lang)}:** {result.started_at[:10]}"
        + (f"  \n**{t(UI, 'commit', lang)}:** {result.git['commit']}" if result.git.get("commit") else ""),
        "",
        f"{t(UI, 'score', lang)}: {result.score}/100, {t(UI, 'grade', lang).lower()} {result.grade}  ",
        f"{t(UI, 'total', lang)}: {len(result.findings)} ("
        + ", ".join(f"{sev[s].lower()}: {c[s]}" for s in SEVERITIES) + ")",
        "",
    ]
    if result.notice:
        lines += [f"> {result.notice.get(lang) or result.notice.get('en', '')}", ""]
    if not result.findings:
        lines += [t(UI, "none", lang), ""]
    for s in SEVERITIES:
        group = [f for f in result.findings if f.severity == s]
        if not group:
            continue
        lines += [f"## {sev[s]} ({len(group)})", ""]
        for f in group:
            if f.locked:
                lines += [f"### 🔒 {f.text('title', lang)}", f"- {t(UI, 'locked_hint', lang)}", ""]
                continue
            lines.append(f"### {f.text('title', lang)}")
            lines.append(f"- {t(UI, 'where', lang)}: `{_where(f, lang)}`")
            if f.detail:
                lines.append(f"- {f.text('detail', lang)}")
            lines.append(f"- {t(UI, 'how_to_fix', lang)}: {f.text('fix', lang)}")
            if f.cwe:
                lines.append(f"- {f.cwe}")
            lines.append("")
    limits = _limits_key(result)
    lines += [f"## {t(UI, 'limits_title', lang)}", "", t(UI, limits, lang), "",
              f"---", f"{t(UI, 'generated', lang)} {__version__} · goldeneye.kz", ""]
    return "\n".join(lines)


CSS = """
:root{--bg:#F4F3EF;--card:#FFFFFF;--ink:#15191C;--muted:#5B625E;--rule:#DDDAD2;--green:#24584A;--gold:#B8913F;
--crit:#A3302A;--high:#B8641E;--med:#8A7A1F;--low:#4F6B78;--code:#F1EFE9;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#121619;--card:#1A1F23;--ink:#E9E7E1;--muted:#A3AAA6;--rule:#2C3338;
--green:#6FAE95;--gold:#D4AC57;--crit:#E0726B;--high:#E39A5B;--med:#CDBB5A;--low:#8FB0BF;--code:#22282D;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 16px 56px;overflow-wrap:anywhere}
.summary>*,.f{min-width:0}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;letter-spacing:.2em;font-size:13px}
.brand i{width:10px;height:10px;border-radius:50%;background:var(--gold);display:inline-block}
h1{font-size:clamp(24px,3.2vw,34px);font-weight:500;margin:18px 0 4px;line-height:1.15}
.meta{color:var(--muted);font-size:14px;display:flex;flex-wrap:wrap;gap:4px 18px}
.summary{display:grid;grid-template-columns:minmax(200px,260px) 1fr;gap:16px;margin:28px 0}
@media (max-width:720px){.summary{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--rule);padding:20px 22px}
.score{display:flex;align-items:baseline;gap:12px}.score b{font-size:56px;font-weight:500;line-height:1}
.score span{color:var(--muted)}.grade{display:inline-grid;place-items:center;width:44px;height:44px;border:2px solid var(--ink);
font-size:22px;font-weight:600;margin-left:auto}
.label{font-size:12px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
.counts{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}@media (max-width:520px){.counts{grid-template-columns:repeat(2,1fr)}}
.count{border-top:3px solid;padding-top:8px}.count b{font-size:28px;font-weight:500;display:block}.count small{color:var(--muted)}
.c-critical{border-color:var(--crit)}.c-high{border-color:var(--high)}.c-medium{border-color:var(--med)}.c-low{border-color:var(--low)}
ol.top{margin:6px 0 0;padding-left:20px}ol.top li{margin:4px 0}
h2{font-size:20px;font-weight:500;margin:36px 0 12px;display:flex;align-items:center;gap:10px}
h2 .dot{width:12px;height:12px;border-radius:50%}
.f{background:var(--card);border:1px solid var(--rule);border-left:4px solid;padding:16px 20px;margin:0 0 10px}
.f h3{margin:0 0 6px;font-size:16px;font-weight:600;line-height:1.35}
.f .loc{font:13px/1.4 ui-monospace,Consolas,monospace;color:var(--muted);word-break:break-all}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}.tag{font-size:12px;border:1px solid var(--rule);padding:1px 8px;color:var(--muted)}
.tag.hist{border-color:var(--gold);color:var(--gold)}
pre{background:var(--code);padding:10px 12px;overflow-x:auto;font:13px/1.45 ui-monospace,Consolas,monospace;margin:8px 0;white-space:pre-wrap;word-break:break-word}
.fix{margin:8px 0 0}.fix b{color:var(--green)}
.note{color:var(--muted);font-size:14px}.warn{border-left:4px solid var(--gold)}
.notice{border:1px solid var(--gold);margin:0 0 16px}.notice p{margin:0}
.f.locked{background:repeating-linear-gradient(135deg,var(--card) 0 12px,var(--code) 12px 24px)}
.cta{background:var(--ink);color:var(--bg);padding:24px;margin-top:36px}.cta h2{margin:0 0 6px;color:inherit}
.cta a{color:var(--gold);font-weight:600}
footer{margin-top:28px;color:var(--muted);font-size:13px}
@media print{body{background:#fff}.f,.card{break-inside:avoid}}
"""

SEV_COLOR = {"critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)", "low": "var(--low)"}


def to_html(result, lang="en") -> str:
    e = html.escape
    c = result.counts
    parts = [f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>GoldenEye Check: {e(result.root.name)}</title><style>{CSS}</style></head><body><main class="wrap">
<div class="brand"><i></i>GOLDENEYE CHECK</div>
<h1>{e(t(UI, 'report_title_site' if result.kind == 'site' else 'report_title', lang))}</h1>
<div class="meta"><span>{e(t(UI, _subject(result), lang))}: <b>{e(result.root.name)}</b></span>
<span>{e(t(UI, 'date', lang))}: {e(result.started_at[:10])}</span>"""]
    if result.git.get("commit"):
        parts.append(f"<span>{e(t(UI, 'commit', lang))}: {e(result.git['commit'])}</span>")
    parts.append("</div>")

    top = [f for f in result.findings if f.severity in ("critical", "high")][:3]
    top_html = "".join(f"<li>{e(f.text('title', lang))} <span class='loc'>({e(_where(f, lang))})</span></li>" for f in top)
    counts_html = "".join(
        f"<div class='count c-{s}'><b>{c[s]}</b><small>{e(t(SEVERITY, s, lang))}</small></div>" for s in SEVERITIES)
    parts.append(f"""<section class="summary">
<div class="card"><p class="label">{e(t(UI, 'score', lang))}</p>
<div class="score"><b>{result.score}</b><span>/ 100</span><span class="grade" title="{e(t(UI, 'grade', lang))}">{result.grade}</span></div></div>
<div class="card"><p class="label">{e(t(UI, 'total', lang))}: {len(result.findings)}</p><div class="counts">{counts_html}</div>
{f"<p class='label' style='margin-top:18px'>{e(t(UI, 'fix_first', lang))}</p><ol class='top'>{top_html}</ol>" if top else ""}
</div></section>""")

    if result.notice:
        parts.append(f"<div class='card notice'><p>{e(result.notice.get(lang) or result.notice.get('en', ''))}</p></div>")

    if result.warnings:
        items = "".join(f"<li>{e(w)}</li>" for w in result.warnings)
        parts.append(f"<div class='card warn'><p class='label'>{e(t(UI, 'skipped', lang))}</p><ul class='note'>{items}</ul></div>")

    if not result.findings:
        parts.append(f"<div class='card'><p>{e(t(UI, 'none', lang))}</p></div>")

    for s in SEVERITIES:
        group = [f for f in result.findings if f.severity == s]
        if not group:
            continue
        parts.append(f"<h2><span class='dot' style='background:{SEV_COLOR[s]}'></span>{e(t(SEVERITY, s, lang))} · {len(group)}</h2>")
        for f in group:
            category = f"<span class='tag'>{e(CATEGORY.get(f.category, {}).get(lang, f.category))}</span>"
            if f.locked:
                parts.append(f"""<article class="f locked" style="border-left-color:{SEV_COLOR[s]}">
<h3>🔒 {e(f.text('title', lang))}</h3><div class="tags">{category}</div>
<p class="note">{e(t(UI, 'locked_hint', lang))}</p></article>""")
                continue
            tags = [category]
            if f.cwe:
                num = f.cwe.split("-")[-1]
                tags.append(f"<a class='tag' href='https://cwe.mitre.org/data/definitions/{e(num)}.html' rel='noopener'>{e(f.cwe)}</a>")
            tags.append(f"<span class='tag'>{e(f.engine)}</span>")
            if f.in_history:
                tags.append(f"<span class='tag hist'>{e(t(UI, 'in_history', lang))}</span>")
            detail = f"<p class='note'>{e(f.text('detail', lang))}</p>" if f.detail else ""
            snippet = f"<pre>{e(f.snippet)}</pre>" if f.snippet else ""
            parts.append(f"""<article class="f" style="border-left-color:{SEV_COLOR[s]}">
<h3>{e(f.text('title', lang))}</h3><div class="loc">{e(_where(f, lang))}</div>
<div class="tags">{''.join(tags)}</div>{detail}{snippet}
<p class="fix"><b>{e(t(UI, 'how_to_fix', lang))}:</b> {e(f.text('fix', lang))}</p></article>""")

    engines = ", ".join(f"{k} {v['version']}" + ("" if v["status"] == "ok" else f" ({v['status']})")
                        for k, v in result.engines.items())
    limits = _limits_key(result)
    parts.append(f"""<h2>{e(t(UI, 'limits_title', lang))}</h2><p class="note">{e(t(UI, limits, lang))}</p>
<section class="cta"><h2>{e(t(UI, 'cta_title', lang))}</h2><p>{e(t(UI, 'cta_text', lang))}</p>
<p><a href="https://goldeneye.kz/{lang}/audit/" rel="noopener">goldeneye.kz</a> · info@goldeneye.kz</p></section>
<footer>{e(t(UI, 'generated', lang))} {__version__} · rules {RULES_VERSION} · {e(t(UI, 'engines', lang))}: {e(engines)} · {result.duration} s</footer>
</main></body></html>""")
    return "\n".join(parts)


def write_reports(result, out_dir: Path, formats, lang="en", include_snippets=False):
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    if "html" in formats:
        p = out_dir / "report.html"
        p.write_text(to_html(result, lang), encoding="utf-8")
        written.append(p)
    if "md" in formats:
        p = out_dir / "report.md"
        p.write_text(to_markdown(result, lang), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = out_dir / "report.json"
        p.write_text(json.dumps(to_json(result, include_snippets), ensure_ascii=False, indent=2), encoding="utf-8")
        written.append(p)
    return written

