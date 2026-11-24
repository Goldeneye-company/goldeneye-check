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
