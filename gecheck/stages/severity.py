"""Stage 8, criticality: chains of findings, problems the project admits, and deployment plans.

Severity of each finding comes from its check (reachability and asset value are part of the checks
of stages 4 and 7). This stage adds what only the whole picture shows:
- chains: two findings that together give an attack worse than each of them;
- known: the README admits the problem; the finding stays, marked as known;
- plans: a reverse proxy in the plans breaks a limit keyed by the client IP.
"""

from ..i18n_code import CODE_WORDS
from .findings import rule_key

# Each chain: two groups of rules; a finding of each group present links them
CHAINS = (
    ({"credentials_in_page", "compose_default_secret", "code_default_secret", "compose_default_password"},
     {"login_no_limit"}),
    ({"no_tls"}, {"cookie_not_secure"}),
    ({"token_in_query"}, {"route_no_store"}),
    ({"object_no_owner"}, {"route_no_audit"}),
)


def apply(findings: list, docs) -> None:
    keys = {}
    for f in findings:
        keys.setdefault(rule_key(f.rule), []).append(f)
    for first, second in CHAINS:
        a = [f for k in first for f in keys.get(k, [])]
        b = [f for k in second for f in keys.get(k, [])]
        if a and b:
            for f in a:
                f.chain = sorted({x.rule for x in b} | set(f.chain))
            for f in b:
                f.chain = sorted({x.rule for x in a} | set(f.chain))
    if docs is None:
        return
    for f in findings:
        if rule_key(f.rule) in docs.known_rules:
            f.known = True
    if docs.plans_proxy:
        for f in keys.get("limit_race", []):
            if "IP" in f.title.get("en", "") and not f.detail:
                f.detail = dict(CODE_WORDS["proxy_plan"])
