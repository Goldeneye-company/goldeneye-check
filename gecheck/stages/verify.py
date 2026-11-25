"""Stage 7, verification: every candidate finding answers four questions (methodology, stage 7).

1. Can it be reached from outside? Command-line tools, tests and migrations are not reachable by a request.
2. Is there a compensating measure nearby? A second factor makes a sign-in without an attempt limit less critical.
3. Does the platform close the problem? (KB entries; used by the stage 5 checks themselves.)
4. Is the strength enough? A short generated password behind an attempt limit is a low risk.

The conditions are the suppress_if of the rules: SUPPRESS maps a rule to a function that returns
None to drop the finding, or the severity to keep.
"""

from .findings import rule_key
from .measures import CODE_EXT, Sources, by_key, reachable

# Rules about code that a web request runs (question 1 applies to them)
REQUEST_RULES = {"login_no_limit", "login_timing", "upload_unprotected", "no_quota", "weak_generated_secret",
                 "limit_race", "per_request_heavy", "credentials_in_page", "cookie_not_secure", "no_error_handler"}


def _mfa_lowers(f, measures):
    # question 2: a second factor stops a password guessed by brute force
    return "high" if "mfa" in measures else f.severity


def _limit_lowers(f, measures):
    # question 4: guessing a short secret online needs many attempts, and the limit stops them
    return "low" if "attempt_limit" in measures else f.severity


SUPPRESS = {
    "login_no_limit": _mfa_lowers,
    "weak_generated_secret": _limit_lowers,
}


def apply(findings: list, sources: Sources, measures: list) -> list:
    m = by_key(measures)
    out = []
    for f in findings:
        key = rule_key(f.rule)
        if key in REQUEST_RULES and f.file.lower().endswith(CODE_EXT) and not reachable(sources, f.file):
            continue
        rule = SUPPRESS.get(key)
        if rule is not None:
            severity = rule(f, m)
            if severity is None:
                continue
            f.severity = severity
        out.append(f)
    return out
