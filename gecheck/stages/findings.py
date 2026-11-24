"""Findings of the methodology checks: texts from i18n, category, controls, effort and stage from RULES."""

from ..i18n import TEXTS, tri
from ..methodology import iso_for
from ..model import Finding

# key: (category, detector, cwe, confidence, effort, stage, extra ISO controls)
RULES = {
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
}


def make(rule_key, severity, path, line=None, anchor=None, snippet=None, **kw) -> Finding:
    category, detector, cwe, confidence, effort, stage, extra = RULES[rule_key]
    return Finding(rule=f"ge.config.{rule_key.replace('_', '-')}", engine="config", severity=severity,
                   category="secrets" if category == "A" else "config", file=path, line=line,
                   title=tri(TEXTS[rule_key]["title"], **kw), fix=tri(TEXTS[rule_key]["fix"], **kw), cwe=cwe,
                   anchor=anchor, snippet=snippet, detector=detector, category_code=category,
                   iso=iso_for(category, extra), confidence=confidence, effort=effort, stage=stage)
