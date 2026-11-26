"""SARIF 2.1.0 report for GitHub code scanning, DefectDojo and other tools that read SARIF.

Code snippets are left out unless include_snippets is set, as in report.json.
"""

from . import RULES_VERSION, __version__
from .i18n import CATEGORY, UI, t

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
REPO = "https://github.com/Goldeneye-company/goldeneye-check"

# SARIF level and GitHub "security-severity" (0-10) for each GoldenEye severity
LEVEL = {"critical": ("error", "9.5"), "high": ("error", "8.0"), "medium": ("warning", "5.5"), "low": ("note", "3.0")}


def _rule(f, lang):
    level, score = LEVEL.get(f.severity, ("warning", "5.0"))
    tags = ["security", CATEGORY.get(f.category, {}).get("en", f.category)]
    if f.cwe:
        tags.append(f"external/cwe/{f.cwe.lower()}")
    rule = {
        "id": f.rule,
        "name": f.rule.rsplit(".", 1)[-1],
        "shortDescription": {"text": f.text("title", lang)},
        "help": {"text": f.text("fix", lang)},
        "defaultConfiguration": {"level": level},
        "properties": {"tags": tags, "security-severity": score, "precision": "high"},
    }
    if f.cwe:
        num = f.cwe.split("-")[-1]
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{num}.html"
    return rule


def _location(f, include_snippets):
    phys = {"artifactLocation": {"uri": f.file}}
    if f.line:
        phys["region"] = {"startLine": f.line}
        if include_snippets and f.snippet:
            phys["region"]["snippet"] = {"text": f.snippet}
    return {"physicalLocation": phys}


def to_sarif(result, lang="en", include_snippets=False) -> dict:
    rules, index, results = [], {}, []
    for f in result.findings:
        if f.rule not in index:
            index[f.rule] = len(rules)
            rules.append(_rule(f, lang))
        text = f.text("title", lang)
        if f.detail:
            text += f". {f.text('detail', lang)}"
        if f.in_history:
            text += f" ({t(UI, 'in_history', lang)}{', ' + f.commit if f.commit else ''})"
        results.append({
            "ruleId": f.rule,
            "ruleIndex": index[f.rule],
            "level": LEVEL.get(f.severity, ("warning",))[0],
            "message": {"text": text},
            "locations": [_location(f, include_snippets)],
            "partialFingerprints": {"goldeneye/v1": f.fingerprint()},
            "properties": {"severity": f.severity, "category": f.category, "engine": f.engine,
                           "inGitHistory": f.in_history,
                           **({"categoryCode": f.category_code, "iso27002": f.iso, "detector": f.detector,
                               "confidence": f.confidence, "effort": f.effort, "stage": f.stage,
                               "known": f.known} if f.category_code else {})},
        })
    run = {
        "tool": {"driver": {
            "name": "GoldenEye Check",
            "version": __version__,
            "semanticVersion": __version__,
            "informationUri": REPO,
            "rules": rules,
            "properties": {"rulesVersion": RULES_VERSION,
                           "engines": {k: v["version"] for k, v in result.engines.items()}},
        }},
        "invocations": [{
            "executionSuccessful": True,
            "toolExecutionNotifications": [{"level": "warning", "message": {"text": w}} for w in result.warnings],
        }],
        "results": results,
        "properties": {"kind": result.kind, "score": result.score, "grade": result.grade,
                       **({"coverage": result.coverage, "preliminary": result.preliminary}
                          if getattr(result, "coverage", None) is not None else {})},
    }
    if result.git.get("commit"):
        # versionControlProvenance would need the repository URL, which reports never include
        run["properties"]["commit"] = result.git["commit"]
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
