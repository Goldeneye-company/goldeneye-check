"""Sections of the methodology report (section 7) for HTML and Markdown.

Order: summary with readiness and the three main problems, confirmed measures, stated against
implemented, findings, ISO/IEC 27001 Annex A summary, roadmap by readiness stage, system model,
coverage and limitations.
"""

import html

from .i18n_report import (ABSENT_NAMES, ASSET_KINDS, CATEGORY_NAMES, CONTROL_NAMES, EFFORT_NAMES, MEASURE_NAMES,
                          PURPOSE_NAMES, REPORT_UI, STAGE_NAMES, SUBJECT_NAMES)
from .methodology import CODE_LANGS, STAGES

e = html.escape


def r(key, lang, **kw) -> str:
    text = REPORT_UI[key].get(lang) or REPORT_UI[key]["en"]
    return text.format(**kw) if kw else text


def name(table, key, lang) -> str:
    entry = table.get(key) or {}
    return entry.get(lang) or entry.get("en") or key


def where(f) -> str:
    return f.file + (f":{f.line}" if f.line else "")


def _lines(lines, n=6) -> str:
    shown = ", ".join(str(x) for x in lines[:n])
    return shown + (", …" if len(lines) > n else "")


def measures_by_key(result) -> list:
    out = {}
    for m in result.measures:
        out.setdefault(m.key, []).append(m)
    return sorted(out.items(), key=lambda kv: (kv[1][0].category, kv[0]))


def finding_tags(f, lang) -> list:
    """Short labels of a finding: category, ISO controls, stage, effort, known, chain."""
    tags = []
    if f.category_code:
        tags.append(f"{f.category_code} · {name(CATEGORY_NAMES, f.category_code, lang)}")
    if f.iso:
        tags.append("ISO " + ", ".join(f.iso))
    if f.stage:
        tags.append(name(STAGE_NAMES, f.stage, lang))
    if f.effort:
        tags.append(f"{r('effort', lang)}: {name(EFFORT_NAMES, f.effort, lang)}")
    if f.known:
        tags.append(r("known", lang))
    if f.chain:
        tags.append(f"{r('chain', lang)} {', '.join(c.rsplit('.', 1)[-1] for c in f.chain)}")
    return tags


def unsupported_languages(result) -> list:
    langs = result.assessment["languages"]
    return sorted(lang for lang in langs if lang not in CODE_LANGS)


def summary_lines(result, lang) -> dict:
    a = result.assessment
    cov = a["coverage"]
    purpose = ", ".join(name(PURPOSE_NAMES, p, lang) for p in a["docs"].purpose)
    return {"verdict": r(a["verdict"], lang),
            "coverage": f"{cov['percent']}% · {r('coverage_text', lang, n=len(cov['categories']))}",
            "preliminary": r("preliminary", lang) if result.preliminary else "",
            "purpose": f"{r('purpose', lang)}: {purpose}." if purpose else ""}


# HTML

def html_summary_extra(result, lang) -> str:
    s = summary_lines(result, lang)
    parts = [f"<p class='label' style='margin-top:18px'>{e(r('readiness', lang))}</p><p><b>{e(s['verdict'])}</b></p>",
             f"<p class='note'>{e(r('coverage', lang))}: {e(s['coverage'])}</p>"]
    if s["preliminary"]:
        parts.append(f"<p class='note'><b>{e(s['preliminary'])}</b></p>")
    if s["purpose"]:
        parts.append(f"<p class='note'>{e(s['purpose'])}</p>")
    return "".join(parts)


def html_before_findings(result, lang) -> str:
    a = result.assessment
    parts = []
    groups = measures_by_key(result)
    if groups:
        items = []
        for key, ms in groups:
            locs = "; ".join(f"{m.file}: {_lines(m.lines)}" for m in ms[:3]) + (" …" if len(ms) > 3 else "")
            items.append(f"<li><b>{e(name(MEASURE_NAMES, key, lang))}</b> <span class='loc'>{e(locs)}</span></li>")
        parts.append(f"<h2>{e(r('s_measures', lang))}</h2><p class='note'>{e(r('s_measures_note', lang))}</p>"
                     f"<div class='card'><ul class='plain'>{''.join(items)}</ul></div>")
    if a["declared"]:
        rows = "".join(
            f"<tr><td>{e(row['claim'].text)}<div class='loc'>{e(row['claim'].file)}:{row['claim'].line}</div></td>"
            f"<td class='st-{row['status']}'>{e(r(row['status'], lang))}</td></tr>" for row in a["declared"])
        parts.append(f"<h2>{e(r('s_declared', lang))}</h2><div class='card tbl'><table>{rows}</table></div>")
    return "".join(parts)


def html_after_findings(result, lang) -> str:
    a = result.assessment
    parts = []
    c = a["controls"]
    names = "".join(f"<li>{e(x)} {e(name(CONTROL_NAMES, x, lang))}</li>" for x in c["process_review"])
    parts.append(f"<h2>{e(r('s_iso', lang))}</h2><div class='card'><p>{e(r('iso_text', lang, total=c['total'], **c['counts']))}</p>"
                 f"<p class='note'>{e(r('process_review', lang))}</p><ul class='note'>{names}</ul>"
                 f"<p class='note'>{e(r('iso_note', lang))}</p></div>")
    stages = []
    for stage in STAGES:
        items = a["roadmap"].get(stage) or []
        if not items:
            continue
        li = "".join(f"<li>{e(f.text('title', lang))} <span class='loc'>({e(where(f))})</span>"
                     f"{' · ' + e(name(EFFORT_NAMES, f.effort, lang)) if f.effort else ''}</li>" for f in items)
        stages.append(f"<h3>{e(name(STAGE_NAMES, stage, lang))} · {len(items)}</h3><ol class='top'>{li}</ol>")
    if stages:
        parts.append(f"<h2>{e(r('s_roadmap', lang))}</h2><div class='card'>{''.join(stages)}</div>")
    parts.append(html_model(result, lang))
    parts.append(html_coverage(result, lang))
    return "".join(parts)


def _yes(v, lang):
    return r("yes", lang) if v else "—"


def html_model(result, lang) -> str:
    m = result.model or {}
    if not m:
        return ""
    parts = [f"<h2>{e(r('s_model', lang))}</h2>"]
    if m.get("assets"):
        rows = "".join(f"<tr><td>{e(x['table'])}</td><td>{e(name(ASSET_KINDS, x['kind'], lang))}</td>"
                       f"<td>{e(', '.join(x['sensitive_columns']))}</td></tr>" for x in m["assets"][:30])
        parts.append(f"<div class='card tbl'><p class='label'>{e(r('assets', lang))}</p><table><tr><th>{e(r('col_table', lang))}</th>"
                     f"<th>{e(r('col_kind', lang))}</th><th>{e(r('col_columns', lang))}</th></tr>{rows}</table></div>")
    if m.get("entry_points"):
        head = "".join(f"<th>{e(x)}</th>" for x in (r("col_route", lang), r("col_signin", lang), r("col_changes", lang),
                                                    "CSRF", r("col_owner", lang), r("col_audit", lang), "no-store"))
        rows = "".join(f"<tr><td>{e(p['method'])} {e(p['route'])}<div class='loc'>{e(p['file'])}:{p['line']}</div></td>"
                       + "".join(f"<td>{e(_yes(p[k], lang))}</td>" for k in ("signed_in", "changes_data", "csrf",
                                                                             "owner_check", "audit_log", "no_store"))
                       + "</tr>" for p in m["entry_points"][:40])
        parts.append(f"<div class='card tbl'><p class='label'>{e(r('routes', lang))}</p><table><tr>{head}</tr>{rows}</table></div>")
    if m.get("subjects"):
        parts.append(f"<p class='note'>{e(r('subjects', lang))}: "
                     f"{e(', '.join(name(SUBJECT_NAMES, s, lang) for s in m['subjects']))}</p>")
    return "".join(parts)


def coverage_items(result, lang) -> list:
    a = result.assessment
    items = []
    missing = a["coverage"]["missing"]
    if missing:
        items.append(r("not_covered", lang) + " " + ", ".join(f"{c} {name(CATEGORY_NAMES, c, lang)}" for c in missing))
    langs = unsupported_languages(result)
    if langs:
        items.append(r("langs_unsupported", lang) + " " + ", ".join(langs))
    absent = result.inventory.absent if result.inventory else []
    if absent:
        items.append(r("absent_files", lang) + " " + ", ".join(name(ABSENT_NAMES, x, lang) for x in absent))
    items.append(r("semantic_off", lang))
    return items


def html_coverage(result, lang) -> str:
    li = "".join(f"<li>{e(x)}</li>" for x in coverage_items(result, lang))
    return f"<h2>{e(r('s_coverage', lang))}</h2><ul class='note'>{li}</ul>"


EXTRA_CSS = """
ul.plain{margin:0;padding-left:18px}ul.plain li{margin:4px 0}
.tbl{overflow-x:auto}.tbl table{border-collapse:collapse;width:100%;font-size:14px}
.tbl th,.tbl td{border-bottom:1px solid var(--rule);padding:6px 8px;text-align:left;vertical-align:top}
.tbl th{font-size:12px;color:var(--muted);font-weight:600}
.st-implemented{color:var(--green)}.st-flawed{color:var(--high)}.st-missing{color:var(--crit)}
.card h3{font-size:15px;margin:14px 0 4px}.card h3:first-child{margin-top:0}
"""


# Markdown

def md_summary_extra(result, lang) -> list:
    s = summary_lines(result, lang)
    out = [f"**{r('readiness', lang)}:** {s['verdict']}  ", f"**{r('coverage', lang)}:** {s['coverage']}  "]
    if s["preliminary"]:
        out.append(f"**{s['preliminary']}**  ")
    if s["purpose"]:
        out.append(s["purpose"])
    return out + [""]


def md_before_findings(result, lang) -> list:
    a = result.assessment
    out = []
    groups = measures_by_key(result)
    if groups:
        out += [f"## {r('s_measures', lang)}", "", r("s_measures_note", lang), ""]
        for key, ms in groups:
            locs = "; ".join(f"`{m.file}`: {_lines(m.lines)}" for m in ms[:3]) + (" …" if len(ms) > 3 else "")
            out.append(f"- **{name(MEASURE_NAMES, key, lang)}** — {locs}")
        out.append("")
    if a["declared"]:
        out += [f"## {r('s_declared', lang)}", ""]
        for row in a["declared"]:
            c = row["claim"]
            out.append(f"- {c.text} (`{c.file}:{c.line}`) — **{r(row['status'], lang)}**")
        out.append("")
    return out


def md_after_findings(result, lang) -> list:
    a = result.assessment
    c = a["controls"]
    out = [f"## {r('s_iso', lang)}", "", r("iso_text", lang, total=c["total"], **c["counts"]), "",
           r("process_review", lang), ""]
    out += [f"- {x} {name(CONTROL_NAMES, x, lang)}" for x in c["process_review"]]
    out += ["", r("iso_note", lang), "", f"## {r('s_roadmap', lang)}", ""]
    for stage in STAGES:
        items = a["roadmap"].get(stage) or []
        if not items:
            continue
        out += [f"### {name(STAGE_NAMES, stage, lang)} ({len(items)})", ""]
        out += [f"{i}. {f.text('title', lang)} — `{where(f)}`" + (f" ({name(EFFORT_NAMES, f.effort, lang)})" if f.effort else "")
                for i, f in enumerate(items, 1)]
        out.append("")
    m = result.model or {}
    if m.get("entry_points"):
        out += [f"## {r('s_model', lang)}", "", f"| {r('col_route', lang)} | {r('col_signin', lang)} | "
                f"{r('col_changes', lang)} | CSRF | {r('col_owner', lang)} | {r('col_audit', lang)} | no-store |",
                "|---|---|---|---|---|---|---|"]
        for p in m["entry_points"][:40]:
            cells = " | ".join(_yes(p[k], lang) for k in ("signed_in", "changes_data", "csrf", "owner_check",
                                                          "audit_log", "no_store"))
            out.append(f"| {p['method']} {p['route']} | {cells} |")
        out.append("")
    out += [f"## {r('s_coverage', lang)}", ""] + [f"- {x}" for x in coverage_items(result, lang)] + [""]
    return out
