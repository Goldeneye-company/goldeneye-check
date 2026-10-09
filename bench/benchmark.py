"""Runs GoldenEye Check on the test project and counts found and missed cases.

Lines marked GE:Vnn contain a vulnerability, GE:Snn safe code. A finding counts
if it points to the same line (for file-level cases, the same file).

    python bench/benchmark.py [--keep]
"""

import argparse
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
    return [(f.file, f.line) for f in result.findings]


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

    rows = score(gecheck_hits(root), markers)
    for cid, (rel, level, desc) in CASES.items():
        hit = rows[cid]
        if cid.startswith("V"):
            mark = "found" if hit else "MISSED"
        else:
            mark = "FALSE POSITIVE" if hit else "ok"
        print(f"{cid:6} {desc[:60]:60} {mark}")

    vulns = [c for c in CASES if c.startswith("V")]
    safe = [c for c in CASES if c.startswith("S")]
    found = sum(rows[c] for c in vulns)
    false = sum(rows[c] for c in safe)
    print()
    print(f"GoldenEye Check: found {found} of {len(vulns)}, false positives {false} of {len(safe)}")

    if args.keep:
        print(f"Test project kept: {root}")
    else:
        remove_tree(root.parent)
    if found < len(vulns) or false:
        sys.exit(1)


if __name__ == "__main__":
    main()
