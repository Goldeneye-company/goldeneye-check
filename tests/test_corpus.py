"""Reference projects: the scanner result is compared with tests/corpus/<name>/expected.json.

Run as a script to print the score: python tests/test_corpus.py
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gecheck.install import NAMES, engine_path  # noqa: E402
from gecheck.scanner import Options, run  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
GRADES = "ABCDF"
SEVERITIES = ("critical", "high", "medium", "low")

# Files that cannot live in this repository (its .gitignore excludes .goldeneye-check/),
# so they are added to the temporary copy before the scan.
EXTRA_FILES = {
    "ghalam": {
        ".goldeneye-check/report.md": "# GoldenEye Check: 192.168.10.25\n\nScore: 100/100 (A)\n",
    },
}


def engines_ready() -> bool:
    return all(engine_path(n).exists() for n in NAMES)


def scan_corpus(name: str):
    src = CORPUS / name
    tmp = Path(tempfile.mkdtemp())
    root = tmp / name
    shutil.copytree(src, root, ignore=shutil.ignore_patterns("expected.json"))
    for rel, text in EXTRA_FILES.get(name, {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    try:
        result = run(root, Options(history=False, deps=False), log=lambda *_: None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return result


def _matches(finding, rel, line, category=None) -> bool:
    if finding.file != rel:
        return False
    if line is not None and finding.line != line:
        return False
    code = getattr(finding, "category_code", None)
    return category is None or code is None or code == category


def compare(result, expected: dict) -> dict:
    found, missed = [], []
    for item in expected["findings"]:
        hit = any(_matches(f, rel, line, item.get("category"))
                  for f in result.findings for rel, line in item["where"])
        (found if hit else missed).append(item)

    false_positives = []
    for measure in expected.get("confirmed", []):
        for f in result.findings:
            for rel, lines in measure["where"]:
                if f.file == rel and f.line in lines and (f.cwe in measure["cwe"]):
                    false_positives.append((measure["id"], f.rule, f.file, f.line))

    total = {s: sum(1 for i in expected["findings"] if i["severity"] == s) for s in SEVERITIES}
    got = {s: sum(1 for i in found if i["severity"] == s) for s in SEVERITIES}
    return {"found": found, "missed": missed, "false_positives": false_positives,
            "total": total, "got": got, "grade": result.grade, "score": result.score,
            "all_findings": result.findings}


def criteria_met(cmp: dict, criteria: dict) -> list:
    """Returns the list of unmet criteria (methodology, section 8)."""
    problems = []
    for sev in SEVERITIES:
        need = criteria.get(sev)
        if need is None:
            continue
        need = cmp["total"][sev] if need == "all" else need
        if cmp["got"][sev] < need:
            problems.append(f"{sev}: {cmp['got'][sev]} of {need} required")
    if cmp["false_positives"]:
        problems.append(f"false positives on confirmed measures: {len(cmp['false_positives'])}")
    max_grade = criteria.get("max_grade")
    if max_grade and GRADES.index(cmp["grade"]) < GRADES.index(max_grade):
        problems.append(f"grade {cmp['grade']}, must be {max_grade} or lower")
    return problems


def describe(name: str, cmp: dict) -> str:
    lines = [f"corpus {name}: score {cmp['score']}, grade {cmp['grade']}"]
    for sev in SEVERITIES:
        lines.append(f"  {sev:8} {cmp['got'][sev]} of {cmp['total'][sev]}")
    if cmp["missed"]:
        lines.append("  missed: " + ", ".join(i["id"] for i in cmp["missed"]))
    for mid, rule, rel, line in cmp["false_positives"]:
        lines.append(f"  false positive on {mid}: {rule} {rel}:{line}")
    known = {(rel, line) for i in cmp["found"] for rel, line in i["where"]}
    extra = [f for f in cmp["all_findings"] if (f.file, f.line) not in known and (f.file, None) not in known]
    for f in extra:
        lines.append(f"  not in expected: {f.rule} {f.severity} {f.file}:{f.line}")
    return "\n".join(lines)


@unittest.skipUnless(engines_ready(), "engines are not installed: gecheck install")
class GhalamCorpusTest(unittest.TestCase):
    """Methodology reference test on the ghalam document portal."""

    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((CORPUS / "ghalam" / "expected.json").read_text(encoding="utf-8"))
        cls.cmp = compare(scan_corpus("ghalam"), cls.expected)
        print("\n" + describe("ghalam", cls.cmp), file=sys.stderr)

    def test_no_regression(self):
        """Never find fewer expected findings than the recorded baseline."""
        for sev, need in self.expected["baseline"].items():
            self.assertGreaterEqual(self.cmp["got"][sev], need, sev)

    def test_no_false_positives_on_confirmed_measures(self):
        self.assertEqual(self.cmp["false_positives"], [])

    def test_methodology_criteria(self):
        if not self.expected.get("strict"):
            self.skipTest("criteria are enforced from version 0.2.0 (strict: true)")
        self.assertEqual(criteria_met(self.cmp, self.expected["criteria"]), [])


if __name__ == "__main__":
    if not engines_ready():
        sys.exit("engines are not installed: gecheck install")
    for path in sorted(CORPUS.glob("*/expected.json")):
        name = path.parent.name
        cmp = compare(scan_corpus(name), json.loads(path.read_text(encoding="utf-8")))
        print(describe(name, cmp))
        problems = criteria_met(cmp, json.loads(path.read_text(encoding="utf-8"))["criteria"])
        print("  criteria: " + ("met" if not problems else "; ".join(problems)))
