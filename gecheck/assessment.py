"""After all engines: the stages of the methodology that need every finding (1, 6, 8, 9, 10) and the coverage.

Findings of the older engines get their category, ISO controls and readiness stage first, so the
roadmap and the ISO summary cover them too.
"""

from . import pro_report
from .methodology import CATEGORIES, classify
from .model import SEV_RANK
from .stages import declaration, iso, readme, roadmap, severity
from .stages.measures import by_key


def assess(result, extras: dict) -> None:
    for f in result.findings:
        classify(f)
    ctx = extras.get("ctx")
    if ctx is None:
        return
    docs = readme.build(ctx)
    measures = by_key(result.measures)
    rows = declaration.assess(docs, result.findings, measures)
    # statements the semantic layer found in free text (stage 1 and 6 in depth)
    seen = {(r["claim"].file, r["claim"].line) for r in rows}
    for n, c in enumerate(extras.get("ai_claims") or [], 1):
        if (c["file"], c["line"]) in seen:
            continue
        seen.add((c["file"], c["line"]))
        claim = readme.Claim(f"ai:{n}", c["category"], c["file"], c["line"], c["text"])
        docs.claims.append(claim)
        rows.append({"claim": claim, "status": c["status"], "findings": [], "source": "semantic",
                     "reason": c.get("reason")})
    result.findings += declaration.findings_for(rows)
    result.findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.file, f.line or 0))
    severity.apply(result.findings, docs)

    languages = [lang for lang in ctx.languages]
    cov = iso.coverage(languages)
    result.coverage = cov["percent"]
    controls = iso.controls(result.findings, result.measures, cov)
    result.assessment = {
        "docs": docs,
        "declared": rows,
        "coverage": cov,
        "languages": dict(ctx.languages),
        "controls": controls,
        "roadmap": roadmap.plan(result.findings),
        "verdict": roadmap.verdict(result.findings),
        "top": roadmap.top(result.findings),
    }
    result.pro = pro_report.build(result)


def to_json(result) -> dict:
    """The assessment part of the JSON report. ISO: totals only (the table of controls is in Pro)."""
    a = getattr(result, "assessment", None)
    if not a:
        return {}
    return {
        "verdict": a["verdict"],
        "coverage": {"percent": a["coverage"]["percent"], "categories": a["coverage"]["categories"],
                     "not_covered": a["coverage"]["missing"], "languages": a["languages"],
                     "preliminary": result.preliminary},
        "docs": a["docs"].to_json(),
        "declared": [{"claim": r["claim"].key, "category_code": r["claim"].category, "file": r["claim"].file,
                      "line": r["claim"].line, "text": r["claim"].text, "status": r["status"],
                      "findings": r["findings"], "source": r.get("source", "dictionary")} for r in a["declared"]],
        "semantic": {k: v for k, v in (result.semantic or {}).items()} or None,
        "iso": {"standard": "ISO/IEC 27002:2022", "total": a["controls"]["total"], "counts": a["controls"]["counts"],
                "process_review": a["controls"]["process_review"]},
        "roadmap": {stage: [f.fingerprint() for f in items] for stage, items in a["roadmap"].items()},
        "categories": {c: info["name"] for c, info in CATEGORIES.items()},
    }
