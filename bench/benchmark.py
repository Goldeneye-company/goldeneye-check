"""Compares GoldenEye Check with another scanner on a test project.

Lines marked GE:Vnn contain a vulnerability, GE:Snn safe code. A finding counts
if it points to the same line (for file-level cases, the same file). For vibe-audit,
any of its findings on that line counts.

    python bench/benchmark.py [--vibe-audit path/to/audit.py] [--keep]
"""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from make_fixture import CASES, build, marker_lines, remove_tree  # noqa: E402

from gecheck.scanner import Options, run  # noqa: E402


def gecheck_hits(root):
    result = run(root, Options(), log=lambda *_: None)
    return [(f.file, f.line) for f in result.findings], result


VA_WHERE = re.compile(r"^- Где: `([^`]+)`", re.M)


def vibe_audit_hits(root, audit_py):
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "va.md"
        subprocess.run([sys.executable, str(audit_py), str(root), "--report", str(report)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       env={"PYTHONIOENCODING": "utf-8", **__import__("os").environ})
        text = report.read_text(encoding="utf-8") if report.exists() else ""
    hits = []
    for where in VA_WHERE.findall(text):
        path, _, line = where.replace("\\", "/").partition(":")
        hits.append((path, int(line) if line.isdigit() else None))
    return hits


def score(hits, markers):
    rows = {}
    for cid, (rel, line) in markers.items():
        if line is None:
            found = any(f == rel for f, _ in hits)
        else:
            found = any(f == rel and ln == line for f, ln in hits)
        rows[cid] = found
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vibe-audit", help="path to vibe-audit/skills/vibe-audit/scripts/audit.py")
    ap.add_argument("--keep", action="store_true", help="keep the test project after the run")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # in a temp folder: osv-scanner honors .gitignore files in parent folders
    root = Path(tempfile.mkdtemp(prefix="gecheck-bench-")) / "fixture"
    build(root)
    markers = marker_lines(root)
    missing = [cid for cid, (rel, line) in markers.items() if CASES[cid][1] == "line" and line is None]
    if missing:
        sys.exit(f"Markers not found in the test project: {missing}")

    tools = {"GoldenEye Check": score(gecheck_hits(root)[0], markers)}
    if args.vibe_audit:
        tools["vibe-audit"] = score(vibe_audit_hits(root, args.vibe_audit), markers)

    names = list(tools)
    print(f"{'case':6} {'description':52} " + " ".join(f"{n:>16}" for n in names))
    for cid, (rel, level, desc) in CASES.items():
        marks = []
        for n in names:
            hit = tools[n][cid]
            if cid.startswith("V"):
                marks.append("found" if hit else "missed")
            else:
                marks.append("FALSE" if hit else "ok")
        print(f"{cid:6} {desc[:52]:52} " + " ".join(f"{m:>16}" for m in marks))

    vulns = [c for c in CASES if c.startswith("V")]
    safe = [c for c in CASES if c.startswith("S")]
    print()
    for n in names:
        found = sum(tools[n][c] for c in vulns)
        false = sum(tools[n][c] for c in safe)
        print(f"{n}: found {found} of {len(vulns)}, false positives {false} of {len(safe)}")

    if args.keep:
        print(f"Test project kept: {root}")
    else:
        remove_tree(root.parent)


if __name__ == "__main__":
    main()
