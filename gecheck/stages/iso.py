"""Stage 9, ISO/IEC 27001:2022 Annex A (controls of ISO/IEC 27002:2022), and the coverage of stage 4.

The status of a control comes from the categories A-O that map to it:
- done: the categories were checked for this stack and nothing is wrong;
- partial: measures are there, but some findings remain, or the findings are medium and low;
- not done: critical or high findings and no measures of the category;
- not assessed: the scanner has no checks of the category for this stack.

Wording in the report: "the code supports the control", never "complies with ISO 27001".
Organisational controls 5.x are assessed only by their technical trace; the rest is listed
for a process review. Lite shows the totals; the table of controls with references is in Pro.
"""

from ..methodology import CATEGORIES, PROCESS_CONTROLS, covered

SEV_BLOCKING = ("critical", "high")


def coverage(languages) -> dict:
    cats = covered(languages)
    return {"categories": cats, "missing": [c for c in CATEGORIES if c not in cats],
            "percent": round(100 * len(cats) / len(CATEGORIES))}


def controls(findings: list, measures: list, cov: dict) -> dict:
    by_cat_findings, by_cat_measures = {}, set()
    for f in findings:
        if f.category_code:
            by_cat_findings.setdefault(f.category_code, []).append(f)
    for m in measures:
        by_cat_measures.add(m.category)
    statuses = {}
    for cat, info in CATEGORIES.items():
        if cat not in cov["categories"]:
            status = "not_assessed"
        else:
            found = by_cat_findings.get(cat, [])
            if not found:
                status = "done"
            elif any(f.severity in SEV_BLOCKING for f in found) and cat not in by_cat_measures:
                status = "not_done"
            else:
                status = "partial"
        for control in info["iso"]:
            statuses.setdefault(control, []).append(status)
    order = ("not_done", "partial", "not_assessed", "done")
    result = {c: min(s, key=order.index) for c, s in statuses.items()}
    counts = {s: sum(1 for v in result.values() if v == s) for s in ("done", "partial", "not_done", "not_assessed")}
    return {"total": len(result), "counts": counts, "statuses": result,
            "process_review": list(PROCESS_CONTROLS)}
