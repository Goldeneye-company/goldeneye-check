"""Stage 10, recommendations and priorities: a roadmap by readiness stage and the verdict of the summary.

Stages: before showing the project outside localhost, before a pilot with real users, before
production, and ISMS processes. Inside a stage the findings go by severity; each has its fix and effort.
"""

from ..methodology import STAGES
from ..model import SEV_RANK

VERDICTS = ("block_localhost", "block_pilot", "block_production", "ready")


def plan(findings: list) -> dict:
    out = {s: [] for s in STAGES}
    for f in findings:
        out.get(f.stage or "production", out["production"]).append(f)
    for s in out:
        out[s].sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.file, f.line or 0))
    return out


def verdict(findings: list) -> str:
    """The earliest stage that a critical or high finding blocks; medium findings block production."""
    for stage, key in (("localhost", "block_localhost"), ("pilot", "block_pilot")):
        if any(f.stage == stage and f.severity in ("critical", "high") for f in findings):
            return key
    if any(f.severity in ("critical", "high", "medium") for f in findings):
        return "block_production"
    return "ready"


def top(findings: list, n: int = 3) -> list:
    """The three problems to fix first: severity, then the earliest stage."""
    order = {s: i for i, s in enumerate(STAGES)}
    return sorted(findings, key=lambda f: (SEV_RANK.get(f.severity, 9), order.get(f.stage, 9),
                                           f.file, f.line or 0))[:n]
