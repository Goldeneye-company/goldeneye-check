"""Check categories A-O and their ISO/IEC 27002:2022 controls.

The code supports a control; it does not make the organisation compliant with ISO/IEC 27001.
"""

CATEGORIES = {
    "A": {"name": "Secrets and defaults", "iso": ["5.17", "8.9"]},
    "B": {"name": "Authentication", "iso": ["8.5", "5.17"]},
    "C": {"name": "Sessions", "iso": ["8.5"]},
    "D": {"name": "Object authorization", "iso": ["5.15", "5.18", "8.3"]},
    "E": {"name": "Input and output", "iso": ["8.28", "8.26"]},
    "F": {"name": "Files", "iso": ["8.7", "8.3", "8.24"]},
    "G": {"name": "Cryptography", "iso": ["8.24", "8.20"]},
    "H": {"name": "Limits and races", "iso": ["8.5", "8.6"]},
    "I": {"name": "Error handling", "iso": ["8.28", "8.9"]},
    "J": {"name": "Logging", "iso": ["8.15", "8.16", "8.17", "5.28"]},
    "K": {"name": "Data lifecycle", "iso": ["8.10", "8.13", "5.33", "5.34"]},
    "L": {"name": "HTTP headers and cache", "iso": ["8.12", "8.26"]},
    "M": {"name": "Infrastructure", "iso": ["8.2", "8.8", "8.9", "8.19", "8.20", "8.21"]},
    "N": {"name": "Repository hygiene", "iso": ["8.25", "8.29", "8.32", "5.14"]},
    "O": {"name": "Availability", "iso": ["8.6"]},
}

DETECTORS = ("pattern", "taint", "absence", "config", "semantic")
CONFIDENCE = ("high", "medium", "low")
EFFORT = ("hours", "days", "weeks")
# When the fix is needed: before any access outside localhost, before a pilot,
# before production, ISMS processes
STAGES = ("localhost", "pilot", "production", "isms")


def iso_for(category: str, extra=()) -> list:
    """Controls of the category plus the finding's own, without duplicates, in order."""
    out = []
    for control in list(CATEGORIES[category]["iso"]) + list(extra):
        if control not in out:
            out.append(control)
    return out


# Languages for which the scanner has checks in each category; "any" means configuration and files
# that do not depend on the language. Coverage = share of categories checked for the project's stack.
CODE_LANGS = ("php", "javascript", "typescript", "python", "java", "go")
CATEGORY_SUPPORT = {
    "A": "any",
    "B": ("php", "javascript", "typescript", "python", "java"),
    "C": ("php", "javascript", "typescript", "python", "java"),
    "D": ("php", "javascript", "typescript", "python", "java"),
    "E": CODE_LANGS,
    "F": CODE_LANGS,
    "G": CODE_LANGS,
    "H": CODE_LANGS,
    "I": ("php", "python", "java", "go"),
    "J": CODE_LANGS,
    "K": "any",
    "L": CODE_LANGS,
    "M": "any",
    "N": "any",
    "O": ("php", "javascript", "typescript", "python", "go"),
}


def covered(languages) -> list:
    """Categories checked for a project with these languages."""
    langs = set(languages)
    return [c for c, support in CATEGORY_SUPPORT.items() if support == "any" or langs & set(support)]


# Organisational controls that code cannot show; the report lists them for a process review
PROCESS_CONTROLS = ("5.1", "5.2", "5.9", "5.24", "5.29", "5.30", "5.36", "6.3")

# Findings of the engines that existed before the methodology: category by the old category and CWE
_BY_CWE = {"CWE-22": "F", "CWE-73": "F", "CWE-434": "F", "CWE-284": "D", "CWE-639": "D", "CWE-862": "D",
           "CWE-352": "E", "CWE-295": "G", "CWE-327": "G", "CWE-328": "G", "CWE-916": "B", "CWE-614": "C",
           "CWE-209": "I", "CWE-215": "I", "CWE-489": "I", "CWE-538": "N", "CWE-200": "L", "CWE-400": "O",
           "CWE-770": "O", "CWE-1104": "M", "CWE-319": "C"}
_BY_OLD = {"secrets": "A", "injection": "E", "auth": "B", "config": "M", "ai-cost": "O", "data-access": "D",
           "dependencies": "M"}
# Readiness stage: secrets and injections must be fixed before the project is shown outside localhost
_STAGE_BY_CATEGORY = {"A": "localhost", "E": "localhost", "D": "pilot", "B": "pilot", "F": "pilot", "O": "pilot",
                      "M": "production", "N": "localhost", "I": "pilot", "C": "pilot", "G": "pilot",
                      "L": "production", "J": "production", "K": "production", "H": "pilot"}


def classify(finding) -> None:
    """Fills the methodology fields of a finding from an older engine (opengrep, gitleaks, osv, builtin)."""
    if finding.category_code:
        return
    code = _BY_CWE.get(finding.cwe or "") if finding.category != "secrets" else "A"
    code = code or _BY_OLD.get(finding.category, "E" if finding.engine.startswith("opengrep") else "M")
    extra = ["8.8"] if finding.category == "dependencies" else []
    finding.category_code = code
    finding.iso = iso_for(code, extra)
    finding.detector = {"opengrep": "pattern", "opengrep-pro": "pattern", "gitleaks": "pattern",
                        "osv-scanner": "config", "builtin": "config"}.get(finding.engine, "pattern")
    finding.confidence = finding.confidence or ("high" if finding.engine in ("gitleaks", "osv-scanner") else "medium")
    finding.effort = finding.effort or ("days" if finding.category == "dependencies" else "hours")
    stage = _STAGE_BY_CATEGORY.get(code, "production")
    if finding.category == "injection":  # any injection is exploitable as soon as anyone can reach the code
        stage = "localhost"
    if finding.category == "dependencies":
        stage = "pilot" if finding.severity in ("critical", "high") else "production"
    finding.stage = finding.stage or stage
