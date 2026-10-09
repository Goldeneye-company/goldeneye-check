"""Поиск секретов через gitleaks в рабочей папке и истории git.

В отчёт попадает только маска значения, в отпечаток находки только его хэш.
"""

import hashlib
import json
import re
import tempfile
from pathlib import Path

from ..i18n import TEXTS, tri
from ..model import SKIP_DIRS, Finding, mask_secret
from .base import rel_path, run_engine

# Названия для отчёта; для остальных правил выводится RuleID
KINDS = {
    "openai-api-key": "OpenAI API key",
    "anthropic-api-key": "Anthropic API key",
    "anthropic-admin-api-key": "Anthropic Admin API key",
    "stripe-access-token": "Stripe secret key",
    "aws-access-token": "AWS access key",
    "github-pat": "GitHub token",
    "github-fine-grained-pat": "GitHub token",
    "gcp-api-key": "Google API key",
    "telegram-bot-api-token": "Telegram bot token",
    "slack-bot-token": "Slack token",
    "private-key": "private key (PEM)",
    "jwt": "JWT",
    "generic-api-key": "API key / password",
}

# Ключи в документации и тестах, а также тестовые ключи Stripe получают уровень medium
DOC_OR_TEST_PATH = re.compile(r"(^|/)(docs?|examples?|samples?|tests?|__tests__|spec|fixtures?|mocks?)(/|$)"
                              r"|\.(md|mdx|rst|txt|adoc)$|[._](test|spec)\.", re.I)
TEST_KEY = re.compile(r"^(sk|rk|pk)_test_", re.I)


def severity_for(file: str, secret: str, rule_id: str) -> str:
    if TEST_KEY.match(secret) or DOC_OR_TEST_PATH.search(file):
        return "medium"
    # generic-api-key срабатывает по эвристике, поэтому high, а не critical
    return "high" if rule_id == "generic-api-key" else "critical"


_SKIP_RE = r"(^|[\\/])(" + "|".join(d.replace(".", r"\.") for d in SKIP_DIRS) + r")([\\/]|$)"
CONFIG = f"""[extend]
useDefault = true

[[allowlists]]
description = "GoldenEye Check: служебные папки и сборки"
paths = ['''{_SKIP_RE}''']
"""


def _run(mode: str, root: Path, config: Path):
    proc = run_engine("gitleaks", [mode, str(root), "--config", str(config), "--report-format", "json",
                                   "--report-path", "-", "--no-banner", "--exit-code", "0",
                                   "--log-level", "error", "--max-target-megabytes", "5"])
    try:
        return json.loads(proc.stdout or "[]") or []
    except json.JSONDecodeError:
        return []


def scan(root: Path, warnings: list, history: bool = True):
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "gitleaks.toml"
        config.write_text(CONFIG, encoding="utf-8")
        current = _run("dir", root, config)
        past = _run("git", root, config) if history and (root / ".git").exists() else []

    findings, seen, current_digests = [], set(), set()
    for leak, from_history in [(x, False) for x in current] + [(x, True) for x in past]:
        file = rel_path(root, leak.get("File", ""))
        secret = leak.get("Secret") or leak.get("Match") or ""
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        # один и тот же секрет в одном файле считаем одной находкой
        if (file, digest) in seen:
            continue
        seen.add((file, digest))
        if not from_history:
            current_digests.add(digest)
        elif digest in current_digests or any(
                f.file == file and f.rule == f"gitleaks.{leak.get('RuleID')}" and not f.in_history for f in findings):
            # уже найден в текущих файлах
            continue
        in_history = from_history
        kind = KINDS.get(leak.get("RuleID", ""), leak.get("RuleID", "secret"))
        masked = mask_secret(secret)
        commit = (leak.get("Commit") or "")[:8] or None
        key = "secret_history" if in_history else "secret"
        detail = (tri(TEXTS["secret_history"]["detail"], commit=commit or "?", masked=masked)
                  if in_history else tri(TEXTS["secret_detail"], masked=masked))
        findings.append(Finding(
            rule=f"gitleaks.{leak.get('RuleID', 'secret')}", engine="gitleaks",
            severity=severity_for(file, secret, leak.get("RuleID", "")), category="secrets", file=file,
            line=None if in_history else leak.get("StartLine"),
            title=tri(TEXTS[key]["title"], kind=kind), fix=tri(TEXTS[key]["fix"]),
            cwe="CWE-798", detail=detail, in_history=in_history, commit=commit, anchor=digest,
        ))
    return findings


def version() -> str:
    from ..install import GITLEAKS
    return GITLEAKS
