"""Report for management and auditors (GoldenEye Check Pro): one printable HTML file and PDF.

Sections: summary, scope and method, confirmed measures, ISO/IEC 27002:2022 controls with evidence,
requirements of Kazakhstan, findings, statements against implementation, self-assessment checklist,
limitations. The PDF is printed from the HTML by an installed Edge, Chrome or Chromium.
"""

import html

from . import RULES_VERSION, __version__
from . import report_sections as rs
from .i18n import SEVERITY, t
from .model import SEVERITIES

e = html.escape

CSS = """
@page{size:A4;margin:18mm 16mm}
*{box-sizing:border-box}body{margin:0;color:#111;background:#fff;font:10.5pt/1.45 "Segoe UI",Arial,sans-serif}
.wrap{max-width:180mm;margin:0 auto;padding:12mm 0}
h1{font-size:20pt;font-weight:600;margin:0 0 2mm}h2{font-size:13pt;margin:8mm 0 3mm;border-bottom:1px solid #999;padding-bottom:1mm}
.sub{color:#444;margin:0 0 6mm}.meta td{padding:1mm 4mm 1mm 0;vertical-align:top}
table{border-collapse:collapse;width:100%;font-size:9pt;margin:2mm 0}
th,td{border:1px solid #bbb;padding:1.5mm 2mm;text-align:left;vertical-align:top}th{background:#eee}
.loc{color:#555;font:8.5pt Consolas,monospace;word-break:break-all}.note{color:#444;font-size:9pt}
.st-done,.st-implemented{color:#1d5e3c}.st-partial,.st-flawed{color:#8a4b0f}.st-not_done,.st-missing{color:#9b1c1c}
.st-not_assessed{color:#666}.big{font-size:14pt;font-weight:600}
.answer{min-width:30mm}section{break-inside:auto}h2{break-after:avoid}tr{break-inside:avoid}
"""


def _sev(s, lang):
    return t(SEVERITY, s, lang)


def to_audit_html(result, lang="ru") -> str:
    a, pro = result.assessment, result.pro
    p, r = rs.p, rs.r
    c = result.counts
    s = rs.summary_lines(result, lang)
    out = [f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<title>{e(p('audit_title', lang))}: {e(result.root.name)}</title><style>{CSS}</style></head><body><main class="wrap">
<h1>{e(p('audit_title', lang))}</h1><p class="sub">{e(p('audit_for', lang))}</p>
<table class="meta"><tr><td>{e(p('project', lang))}</td><td><b>{e(result.root.name)}</b></td></tr>
<tr><td>{e(p('check_date', lang))}</td><td>{e(result.started_at[:10])}</td></tr>"""]
    if result.git.get("commit"):
        out.append(f"<tr><td>commit</td><td>{e(result.git['commit'])}</td></tr>")
    out.append("</table>")

    # 1. Summary
    top = "".join(f"<li>{e(f.text('title', lang))} <span class='loc'>{e(rs.where(f))}</span></li>" for f in a["top"])
    counts = ", ".join(f"{_sev(x, lang).lower()}: {c[x]}" for x in SEVERITIES)
    out.append(f"""<h2>{e(p('a_summary', lang))}</h2>
<p class="big">{e(s['verdict'])}</p>
<p><b>{e(p('score_line', lang, score=result.score, grade=result.grade))}</b> {e(r('coverage', lang))}: {e(s['coverage'])}.
{e(s['preliminary'])}</p><p>{e(counts)}.</p>{f'<p>{e(s["purpose"])}</p>' if s['purpose'] else ''}
<p>{e(r('iso_text', lang, total=len(pro['controls']), **pro['counts']))}</p><ol>{top}</ol>""")

    # 2. Scope and method
    langs = ", ".join(f"{k} ({v})" for k, v in sorted(a["languages"].items()))
    engines = ", ".join(f"{k} {v.get('version', '')}".strip() for k, v in result.engines.items() if v.get("status") == "ok")
    versions = ", ".join(f"{k} {v}" for k, v in pro["versions"].items())
    out.append(f"""<h2>{e(p('a_scope', lang))}</h2><p>{e(p('method', lang))}</p>
<table class="meta"><tr><td>{e(p('languages', lang))}</td><td>{e(langs or '—')}</td></tr>
<tr><td>{e(p('tools', lang))}</td><td>GoldenEye Check {e(__version__)} · rules {e(RULES_VERSION)} · Pro {e(result.options.pro_version or '—')} · {e(engines)}</td></tr>
<tr><td>{e(p('data_versions', lang))}</td><td>{e(versions)}</td></tr></table>
<p class="note">{e(p('issued', lang, account=pro.get('issued_to') or '—', date=pro.get('issued_on') or '—'))}</p>""")

    # 3. Confirmed measures
    rows = "".join(f"<tr><td>{e(rs.name(rs.MEASURE_NAMES, key, lang))}</td><td class='loc'>"
                   f"{e('; '.join(f'{m.file}: {rs._lines(m.lines, 8)}' for m in ms))}</td></tr>"
                   for key, ms in rs.measures_by_key(result))
    out.append(f"<h2>{e(p('a_measures', lang))}</h2><table>{rows or '<tr><td>—</td></tr>'}</table>")

    # 4-5. ISO and Kazakhstan: the same tables as in the main report
    iso_rows = "".join(
        f"<tr><td><b>{e(x['id'])}</b> {e(rs._t(x['title'], lang))}</td><td class='st-{x['status']}'>"
        f"{e(p('status_' + x['status'], lang))}</td><td>{''.join(f'<div>{e(i)}</div>' for i in rs.evidence_items(x, lang, 6)) or '—'}</td></tr>"
        for x in pro["controls"])
    note = "" if pro["national"].get("verified") else f"<p class='note'>{e(rs._t(pro['national'].get('note'), lang))}</p>"
    out.append(f"<h2>{e(p('a_iso', lang))}</h2>{note}<table><tr><th>{e(p('col_control', lang))}</th>"
               f"<th>{e(p('col_status', lang))}</th><th>{e(p('col_evidence', lang))}</th></tr>{iso_rows}</table>")
    sources = "".join(f"<p class='note'><b>{e(rs._t(src.get('title'), lang))}</b>. {e(rs._t(src.get('applies'), lang))}</p>"
                      for src in pro["sources"])
    kz_rows = "".join(
        f"<tr><td><b>{e(q['ref'])}</b> {e(rs._t(q['text'], lang))}"
        f"{'<div class=note>' + e(p('partial_req', lang)) + '</div>' if q.get('partial') else ''}</td>"
        f"<td>{e(', '.join(q['controls']))}</td><td class='st-{q['status']}'>{e(p('status_' + q['status'], lang))}</td></tr>"
        for q in pro["requirements"])
    out.append(f"<h2>{e(p('a_kz', lang))}</h2>{sources}<table><tr><th>{e(p('col_req', lang))}</th><th>ISO</th>"
               f"<th>{e(p('col_status', lang))}</th></tr>{kz_rows}</table><p class='note'>{e(p('kz_note', lang))}</p>")

    # 6. Findings
    f_rows = "".join(
        f"<tr><td>{e(_sev(f.severity, lang))}</td><td>{e(f.text('title', lang))}<div class='loc'>{e(rs.where(f))}</div>"
        f"<div class='note'>{e(f.text('fix', lang))}</div></td><td>{e(f.cwe or '—')}</td><td>{e(', '.join(f.iso or []))}</td>"
        f"<td>{e(rs.name(rs.STAGE_NAMES, f.stage, lang) if f.stage else '—')}</td></tr>" for f in result.findings)
    out.append(f"<h2>{e(p('a_findings', lang))}</h2><table><tr><th>{e(p('col_severity', lang))}</th>"
               f"<th>{e(p('col_finding', lang))}</th><th>CWE</th><th>ISO</th>"
               f"<th>{e(rs.r('s_roadmap', lang))}</th></tr>{f_rows or '<tr><td>—</td></tr>'}</table>")

    # 7. Statements
    if a["declared"]:
        d_rows = "".join(f"<tr><td>{e(x['claim'].text)}<div class='loc'>{e(x['claim'].file)}:{x['claim'].line}</div></td>"
                         f"<td class='st-{x['status']}'>{e(r(x['status'], lang))}</td></tr>" for x in a["declared"])
        out.append(f"<h2>{e(p('a_declared', lang))}</h2><table>{d_rows}</table>")

    # 8. Checklist
    c_rows = "".join(f"<tr><td>{e(i['control'])}</td><td>{e(rs._t(i['question'], lang))}</td>"
                     f"<td class='note'>{e(rs._t(i['evidence'], lang))}</td><td class='answer'></td></tr>" for i in pro["checklist"])
    out.append(f"<h2>{e(p('a_checklist', lang))}</h2><p class='note'>{e(p('checklist_note', lang))}</p>"
               f"<table><tr><th>ISO</th><th>{e(p('col_question', lang))}</th><th>{e(p('col_proof', lang))}</th>"
               f"<th>{e(p('col_answer', lang))}</th></tr>{c_rows}</table>")

    # 9. Limitations
    items = "".join(f"<li>{e(x)}</li>" for x in rs.coverage_items(result, lang))
    out.append(f"<h2>{e(p('a_limits', lang))}</h2><ul>{items}</ul><p><b>{e(p('disclaimer', lang))}</b></p>"
               f"</main></body></html>")
    return "\n".join(out)
