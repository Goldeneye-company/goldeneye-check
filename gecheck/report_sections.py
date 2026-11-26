"""Sections of the methodology report (section 7) for HTML and Markdown.

Order: summary with readiness and the three main problems, confirmed measures, stated against
implemented, findings, ISO/IEC 27001 Annex A summary, roadmap by readiness stage, system model,
coverage and limitations.
"""

import html

from .i18n_report import (ABSENT_NAMES, ASSET_KINDS, CATEGORY_NAMES, CONTROL_NAMES, EFFORT_NAMES, MEASURE_NAMES,
                          PRO_UI, PURPOSE_NAMES, REPORT_UI, STAGE_NAMES, SUBJECT_NAMES)
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


def p(key, lang, **kw) -> str:
    text = PRO_UI[key].get(lang) or PRO_UI[key]["en"]
    return text.format(**kw) if kw else text


def _t(entry, lang) -> str:
    return (entry or {}).get(lang) or (entry or {}).get("en") or ""


def evidence_items(control, lang, limit=4) -> list:
    """Short lines: measures with lines, then findings with places."""
    items = [f"✓ {name(MEASURE_NAMES, m.key, lang)} — {m.file}: {_lines(m.lines, 4)}" for m in control["measures"][:limit]]
    items += [f"✗ {f.text('title', lang)} — {where(f)}" for f in control["findings"][:limit]]
    return items


def html_pro(result, lang) -> str:
    pro = result.pro
    rows = []
    for c in pro["controls"]:
        ev = "".join(f"<div>{e(x)}</div>" for x in evidence_items(c, lang)) or "—"
        rows.append(f"<tr><td><b>{e(c['id'])}</b> {e(_t(c['title'], lang))}<div class='loc'>{e(_t(c['shows'], lang))}</div></td>"
                    f"<td class='st-{c['status']}'>{e(p('status_' + c['status'], lang))}</td><td class='ev'>{ev}</td></tr>")
    counts = pro["counts"]
    national = pro["national"]
    note = "" if national.get("verified") else f"<p class='note'>{e(_t(national.get('note'), lang))}</p>"
    parts = [f"<h2>{e(p('s_iso_table', lang))}</h2><div class='card tbl'>"
             f"<p>{e(r('iso_text', lang, total=len(pro['controls']), **counts))}</p>{note}"
             f"<table><tr><th>{e(p('col_control', lang))}</th><th>{e(p('col_status', lang))}</th>"
             f"<th>{e(p('col_evidence', lang))}</th></tr>{''.join(rows)}</table>"
             f"<p class='note'>{e(r('iso_note', lang).split('. ')[0])}.</p></div>"]
    kz = []
    for req in pro["requirements"]:
        partial = f"<div class='loc'>{e(p('partial_req', lang))}</div>" if req.get("partial") else ""
        found = "".join(f"<div>✗ {e(f.text('title', lang))} — {e(where(f))}</div>" for f in req["findings"][:3]) or "—"
        kz.append(f"<tr><td><b>{e(req['ref'])}</b> {e(_t(req['text'], lang))}{partial}</td>"
                  f"<td>{e(', '.join(req['controls']))}</td><td class='st-{req['status']}'>"
                  f"{e(p('status_' + req['status'], lang))}</td><td class='ev'>{found}</td></tr>")
    sources = "".join(f"<p class='note'><b>{e(_t(s.get('title'), lang))}</b>. {e(_t(s.get('applies'), lang))}</p>"
                      for s in pro["sources"])
    parts.append(f"<h2>{e(p('s_kz', lang))}</h2><div class='card tbl'>{sources}<table><tr><th>{e(p('col_req', lang))}</th>"
                 f"<th>ISO</th><th>{e(p('col_status', lang))}</th><th>{e(p('col_evidence', lang))}</th></tr>"
                 f"{''.join(kz)}</table><p class='note'>{e(p('kz_note', lang))}</p></div>")
    items = "".join(f"<tr><td>{e(i['control'])}</td><td>{e(_t(i['question'], lang))}</td>"
                    f"<td class='loc'>{e(_t(i['evidence'], lang))}</td><td class='answer'></td></tr>" for i in pro["checklist"])
    parts.append(f"<h2>{e(p('s_checklist', lang))}</h2><div class='card tbl'><p class='note'>{e(p('checklist_note', lang))}</p>"
                 f"<table><tr><th>ISO</th><th>{e(p('col_question', lang))}</th><th>{e(p('col_proof', lang))}</th>"
                 f"<th>{e(p('col_answer', lang))}</th></tr>{items}</table></div>")
    return "".join(parts)


def md_pro(result, lang) -> list:
    pro = result.pro
    out = [f"## {p('s_iso_table', lang)}", "", r("iso_text", lang, total=len(pro["controls"]), **pro["counts"]), ""]
    if not pro["national"].get("verified"):
        out += [_t(pro["national"].get("note"), lang), ""]
    out += [f"| {p('col_control', lang)} | {p('col_status', lang)} | {p('col_evidence', lang)} |", "|---|---|---|"]
    for c in pro["controls"]:
        ev = "<br>".join(x.replace("|", "\\|") for x in evidence_items(c, lang, 3)) or "—"
        out.append(f"| {c['id']} {_t(c['title'], lang)} | {p('status_' + c['status'], lang)} | {ev} |")
    out += ["", f"## {p('s_kz', lang)}", ""]
    for s in pro["sources"]:
        out += [f"**{_t(s.get('title'), lang)}**. {_t(s.get('applies'), lang)}", ""]
    out += [f"| {p('col_req', lang)} | ISO | {p('col_status', lang)} |", "|---|---|---|"]
    for req in pro["requirements"]:
        mark = " *" if req.get("partial") else ""
        out.append(f"| {req['ref']} {_t(req['text'], lang)}{mark} | {', '.join(req['controls'])} | "
                   f"{p('status_' + req['status'], lang)} |")
    out += ["", f"\\* {p('partial_req', lang)}. {p('kz_note', lang)}", "", f"## {p('s_checklist', lang)}", "",
            p("checklist_note", lang), ""]
    out += [f"- [ ] **{i['control']}** {_t(i['question'], lang)} — {_t(i['evidence'], lang)}" for i in pro["checklist"]]
    return out + [""]


def html_after_findings(result, lang) -> str:
    a = result.assessment
    parts = []
    c = a["controls"]
    if result.pro:
        parts.append(html_pro(result, lang))
    else:
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
    s = getattr(result, "semantic", None) or {}
    if s.get("status") == "done":
        items.append(r("semantic_done", lang, model=s["model"], routes=s["routes"], findings=s.get("findings", 0),
                       dropped=s.get("dropped", 0)))
        if s.get("skipped"):
            items.append(r("semantic_skipped", lang, names=", ".join(s["skipped"][:10])))
    else:
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
.st-implemented,.st-done{color:var(--green)}.st-flawed,.st-partial{color:var(--high)}
.st-missing,.st-not_done{color:var(--crit)}.st-not_assessed{color:var(--muted)}
.tbl td.ev{font-size:13px}.tbl td.ev div{margin:2px 0}.tbl td.answer{min-width:120px}
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
    if result.pro:
        out = md_pro(result, lang)
    else:
        out = [f"## {r('s_iso', lang)}", "", r("iso_text", lang, total=c["total"], **c["counts"]), "",
               r("process_review", lang), ""]
        out += [f"- {x} {name(CONTROL_NAMES, x, lang)}" for x in c["process_review"]]
        out += ["", r("iso_note", lang), ""]
    out += [f"## {r('s_roadmap', lang)}", ""]
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
