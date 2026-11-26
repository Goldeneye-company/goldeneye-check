"""Pro sections of the report: the table of ISO/IEC 27002 controls with evidence, the requirements of
Kazakhstan, the self-assessment checklist and the report for an auditor (HTML, and PDF through a browser).

The tables themselves (controls with titles, requirements, checklist questions) are not in this code:
the goldeneye.kz server sends them with the Pro rules for one check. This module only puts the
results of the check against them.
"""

import shutil
import subprocess
from pathlib import Path

from .model import SEV_RANK
from .stages import iso

LANGS = ("ru", "kk", "en")


def valid(data) -> bool:
    return (isinstance(data, dict) and isinstance(data.get("iso27002", {}).get("controls"), dict)
            and isinstance(data.get("kz", {}).get("requirements"), list)
            and isinstance(data.get("checklist", {}).get("items"), list))


def _text(entry, lang) -> str:
    if isinstance(entry, dict):
        return str(entry.get(lang) or entry.get("en") or "")
    return str(entry or "")


def build(result) -> dict:
    """Pro data for the report, or None without Pro tables."""
    data = getattr(result.options, "pro_compliance", None)
    a = getattr(result, "assessment", None)
    if not a or not valid(data):
        return None
    cats = iso.category_statuses(result.findings, result.measures, a["coverage"])
    by_cat_findings, by_cat_measures = {}, {}
    for f in result.findings:
        if f.category_code:
            by_cat_findings.setdefault(f.category_code, []).append(f)
    for m in result.measures:
        by_cat_measures.setdefault(m.category, []).append(m)

    def evidence(categories):
        measures = [m for c in categories for m in by_cat_measures.get(c, [])]
        findings = sorted({id(f): f for c in categories for f in by_cat_findings.get(c, [])}.values(),
                          key=lambda f: (SEV_RANK.get(f.severity, 9), f.file, f.line or 0))
        return measures, findings

    controls = []
    for cid, c in sorted(data["iso27002"]["controls"].items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        categories = [x for x in c.get("categories", []) if x in cats]
        measures, findings = evidence(categories)
        controls.append({"id": cid, "title": c.get("title", {}), "shows": c.get("shows", {}),
                         "status": iso.worst(cats[x] for x in categories), "measures": measures, "findings": findings})
    counts = {s: sum(1 for c in controls if c["status"] == s) for s in iso.ORDER}

    present = {m.key for m in result.measures}
    requirements = []
    for r in data["kz"]["requirements"]:
        categories = [x for x in r.get("categories", []) if x in cats]
        _measures, findings = evidence(categories)
        status = iso.worst(cats[x] for x in categories)
        needed = r.get("measures") or []
        if needed and not any(m in present for m in needed) and status != "not_assessed":
            status = "not_done"   # the requirement names a measure, and the code does not have it
        elif r.get("partial") and status == "done":
            status = "partial"    # the code shows only its part; the rest is checked through documents
        requirements.append({**r, "status": status, "findings": findings})
    return {"controls": controls, "counts": counts, "requirements": requirements,
            "sources": data["kz"].get("sources", []), "national": data["iso27002"].get("national", {}),
            "checklist": data["checklist"]["items"], "versions": {k: data[k].get("version") for k in
                                                                  ("iso27002", "kz", "checklist")},
            "issued_to": data.get("issued_to"), "issued_on": data.get("issued_on")}


def to_json(pro: dict) -> dict:
    """Pro part of report.json: statuses and references, without the texts of the tables."""
    if not pro:
        return None
    return {
        "versions": pro["versions"],
        "controls": [{"id": c["id"], "status": c["status"],
                      "measures": [{"key": m.key, "file": m.file, "lines": m.lines} for m in c["measures"]],
                      "findings": [f.fingerprint() for f in c["findings"]]} for c in pro["controls"]],
        "counts": pro["counts"],
        "requirements": [{"id": r["id"], "source": r["source"], "ref": r["ref"], "controls": r["controls"],
                          "status": r["status"], "partial": r.get("partial", False),
                          "findings": [f.fingerprint() for f in r["findings"]]} for r in pro["requirements"]],
        "national_verified": bool(pro["national"].get("verified")),
    }


# PDF: the auditor report is printed by an installed Chromium browser (Edge or Chrome), no extra packages

BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)
BROWSER_NAMES = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge",
                 "msedge", "chrome")


def find_browser():
    for name in BROWSER_NAMES:
        path = shutil.which(name)
        if path:
            return path
    return next((p for p in BROWSERS if Path(p).exists()), None)


def print_pdf(html_path: Path, pdf_path: Path, browser=None) -> bool:
    browser = browser or find_browser()
    if not browser:
        return False
    profile = pdf_path.parent / ".pdf-profile"
    try:
        subprocess.run([browser, "--headless", "--disable-gpu", "--no-first-run", "--no-pdf-header-footer",
                        f"--user-data-dir={profile}", f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()],
                       capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    return pdf_path.exists() and pdf_path.stat().st_size > 0
