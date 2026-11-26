"""Findings of the methodology checks: texts from i18n, category, controls, effort and stage from RULES."""

from ..i18n import LANGS, TEXTS
from ..methodology import iso_for
from ..model import Finding

# key: (category, detector, cwe, confidence, effort, stage, extra ISO controls)
RULES = {
    # stage 5 and the configuration checks (step 1)
    "code_default_secret":   ("A", "pattern", "CWE-1393", "high", "hours", "localhost", []),
    "compose_default_secret": ("A", "config", "CWE-1393", "high", "hours", "localhost", []),
    "credentials_in_page":   ("A", "pattern", "CWE-798", "high", "hours", "localhost", []),
    "cookie_not_secure":     ("C", "pattern", "CWE-614", "high", "hours", "pilot", ["8.24"]),
    "no_tls":                ("C", "config", "CWE-319", "high", "days", "pilot", ["8.20", "8.24", "5.14"]),
    "php_display_errors":    ("I", "config", "CWE-209", "high", "hours", "localhost", []),
    "php_expose":            ("I", "config", "CWE-200", "high", "hours", "localhost", []),
    "php_session_strict":    ("C", "config", "CWE-384", "high", "hours", "pilot", []),
    "php_timezone":          ("J", "config", "CWE-1389", "medium", "hours", "production", []),
    "server_tokens":         ("M", "config", "CWE-200", "high", "hours", "localhost", []),
    "db_superuser":          ("M", "config", "CWE-250", "high", "days", "pilot", ["8.3", "8.18"]),
    "container_hardening":   ("M", "config", "CWE-250", "medium", "hours", "production", []),
    "image_unpinned":        ("M", "config", "CWE-1357", "medium", "hours", "production", []),
    "build_image_runtime":   ("M", "config", "CWE-1104", "high", "hours", "production", []),
    "java_debug_port":       ("M", "config", "CWE-489", "high", "hours", "localhost", ["8.31"]),
    "jmx_no_auth":           ("M", "config", "CWE-306", "high", "hours", "localhost", []),
    "tomcat_manager":        ("M", "config", "CWE-1188", "high", "hours", "pilot", []),
    "spring_actuator_exposed": ("M", "config", "CWE-215", "high", "hours", "localhost", ["8.12"]),
    "spring_h2_console":     ("M", "config", "CWE-489", "high", "hours", "localhost", []),
    "spring_stacktrace":     ("I", "config", "CWE-209", "high", "hours", "localhost", []),
    "gin_debug":             ("I", "config", "CWE-489", "medium", "hours", "pilot", []),
    "go_pprof":              ("I", "pattern", "CWE-215", "high", "hours", "localhost", ["8.12"]),
    "go_http_timeouts":      ("O", "pattern", "CWE-400", "high", "hours", "pilot", []),
    # stage 4: missing measures and code patterns (step 2)
    "login_no_limit":        ("B", "absence", "CWE-307", "medium", "days", "pilot", []),
    "login_timing":          ("B", "pattern", "CWE-208", "medium", "hours", "production", []),
    "no_account_management": ("B", "absence", "CWE-620", "medium", "days", "pilot", ["5.16", "5.18"]),
    "upload_unprotected":    ("F", "absence", "CWE-311", "medium", "days", "pilot", []),
    "weak_generated_secret": ("G", "pattern", "CWE-331", "high", "hours", "pilot", []),
    "limit_race":            ("H", "pattern", "CWE-362", "medium", "hours", "pilot", []),
    "no_error_handler":      ("I", "absence", "CWE-755", "medium", "hours", "pilot", []),
    "no_deletion":           ("K", "absence", "CWE-459", "medium", "days", "production", []),
    "no_backup":             ("K", "absence", None, "medium", "days", "production", []),
    "per_request_heavy":     ("O", "pattern", "CWE-400", "high", "hours", "pilot", []),
    "no_quota":              ("O", "absence", "CWE-770", "medium", "hours", "production", []),
    # stage 2: repository hygiene
    "repo_artifact":         ("N", "absence", "CWE-538", "high", "hours", "localhost", []),
    # stage 4 on routes: the route x measure matrix (step 3)
    "route_no_audit":        ("J", "absence", "CWE-778", "medium", "days", "pilot", []),
    "route_no_store":        ("L", "absence", "CWE-525", "medium", "hours", "pilot", []),
    "object_no_owner":       ("D", "absence", "CWE-639", "medium", "days", "pilot", []),
    "csrf_missing":          ("E", "absence", "CWE-352", "medium", "hours", "pilot", []),
    "logout_get":            ("E", "pattern", "CWE-352", "high", "hours", "production", []),
    "token_in_query":        ("J", "pattern", "CWE-598", "medium", "hours", "production", ["8.12"]),
    "host_header_url":       ("E", "pattern", "CWE-644", "medium", "hours", "production", []),
    "secret_in_session":     ("G", "pattern", "CWE-312", "medium", "hours", "production", []),
    "session_no_timeout":    ("C", "absence", "CWE-613", "medium", "hours", "pilot", []),
    "csp_missing":           ("L", "absence", "CWE-693", "high", "hours", "production", []),
    "error_path_unhandled":  ("I", "pattern", "CWE-755", "medium", "hours", "pilot", []),
    # stage 6: a measure the README states and the code does not implement (category of the claim)
    "declared_not_implemented": ("N", "absence", None, "high", "days", "pilot", []),
}

PREFIX = {key: "ge.code" for key in ("login_no_limit", "login_timing", "no_account_management", "upload_unprotected",
                                      "weak_generated_secret", "limit_race", "no_error_handler", "no_deletion",
                                      "no_backup", "per_request_heavy", "no_quota", "secret_in_session",
                                      "session_no_timeout", "csp_missing")}
PREFIX.update({key: "ge.route" for key in ("route_no_audit", "route_no_store", "object_no_owner", "csrf_missing",
                                           "logout_get", "token_in_query", "host_header_url", "error_path_unhandled")})
PREFIX["repo_artifact"] = "ge.repo"
PREFIX["declared_not_implemented"] = "ge.docs"


def rule_id(rule_key: str) -> str:
    return f"{PREFIX.get(rule_key, 'ge.config')}.{rule_key.replace('_', '-')}"


def rule_key(rule: str) -> str:
    """'ge.code.login-no-limit' -> 'login_no_limit'."""
    return rule.rsplit(".", 1)[-1].replace("-", "_")


def _fill(entry: dict, kw: dict) -> dict:
    """A parameter may be a plain value or a {lang: value} dict for words that differ by language."""
    return {lang: entry[lang].format(**{k: (v[lang] if isinstance(v, dict) else v) for k, v in kw.items()})
            for lang in LANGS}


def make(rule_key, severity, path, line=None, anchor=None, snippet=None, cwe=None, category_override=None,
         **kw) -> Finding:
    category, detector, default_cwe, confidence, effort, stage, extra = RULES[rule_key]
    category = category_override or category
    return Finding(rule=rule_id(rule_key), engine="config", severity=severity,
                   category="secrets" if category == "A" else "config", file=path, line=line,
                   title=_fill(TEXTS[rule_key]["title"], kw), fix=_fill(TEXTS[rule_key]["fix"], kw),
                   cwe=cwe or default_cwe, anchor=anchor, snippet=snippet, detector=detector,
                   category_code=category, iso=iso_for(category, extra), confidence=confidence,
                   effort=effort, stage=stage)
