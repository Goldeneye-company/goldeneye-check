"""Stage 6, declaration against implementation: every measure the README states gets a status.

- implemented: the measure is in the code and no finding says it is broken;
- implemented with flaws: the measure is there, but findings show a weakness (a lockout with a race);
- not implemented: the measure is missing.

A measure that is stated and not implemented is a finding of its own: the README makes users
and auditors rely on something the code does not do.
"""

from .findings import make, rule_key

# claim key: (measures that implement it, findings that mean it is missing, findings that mean it is weak)
CLAIM_RULES = {
    "mfa": (("mfa",), (), ("login_no_limit",)),
    "attempt_limit": (("attempt_limit",), (), ("limit_race", "login_no_limit", "weak_generated_secret")),
    "audit_log": (("audit_log",), (), ("route_no_audit", "token_in_query")),
    "encryption": (("encryption_at_rest",), (), ("upload_unprotected:CWE-311", "secret_in_session")),
    "antivirus": (("antivirus",), (), ()),
    "integrity": (("integrity_hash",), (), ()),
    "https": ((), ("no_tls",), ("cookie_not_secure",)),
    "csp": ((), ("csp_missing",), ()),
    "no_cache": ((), ("route_no_store",), ()),
    "backup": (("backup",), ("no_backup",), ()),
    "retention": (("retention", "deletion"), ("no_deletion",), ()),
    "roles": ((), (), ("object_no_owner",)),
    "random_secrets": (("strong_random",), (), ("weak_generated_secret",)),
    "secrets_excluded": (("env_ignored",), (), ("repo_artifact", "env_not_ignored")),
}
STATUSES = ("implemented", "flawed", "missing")


def _hits(findings: list, specs) -> list:
    out = []
    for spec in specs:
        key, _, cwe = spec.partition(":")
        out += [f for f in findings if rule_key(f.rule) == key and (not cwe or f.cwe == cwe)]
    return out


def assess(docs, findings: list, measures: dict) -> list:
    """Rows of the "declared / implemented" table: (claim, status, findings that explain it)."""
    rows = []
    for claim in docs.claims:
        implementing, absent, weak = CLAIM_RULES.get(claim.key, ((), (), ()))
        missing = _hits(findings, absent)
        flaws = _hits(findings, weak)
        if missing or (implementing and not any(m in measures for m in implementing)):
            status = "missing"
        elif flaws:
            status = "flawed"
        else:
            status = "implemented"
        rows.append({"claim": claim, "status": status, "findings": [f.rule for f in missing + flaws]})
    return rows


def findings_for(rows: list) -> list:
    """A stated measure that the code does not implement."""
    out = []
    for row in rows:
        if row["status"] != "missing":
            continue
        c = row["claim"]
        out.append(make("declared_not_implemented", "medium", c.file, c.line, anchor=f"declared:{c.key}",
                        category_override=c.category, text=c.text[:120]))
    return out
