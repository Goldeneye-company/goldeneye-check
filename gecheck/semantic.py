"""The semantic layer (GoldenEye Check Pro): a language model reviews what patterns cannot see.

Access logic, information shown before authentication, secrets delivered together with what they
protect, races, and free-text statements of the documentation. The instructions for the model come
from the goldeneye.kz server with the Pro rules; the model is called from this computer with the
customer's own key (Anthropic SDK credentials), so the code goes to the model provider and not to
goldeneye.kz. What is sent: the handlers of the routes and the functions they call, with line numbers,
the documentation files, and the summary the static checks built. Lines that look like secrets are
masked before sending.

Every answer is checked before it becomes a finding: the file and line must exist in what was sent,
the quoted evidence must be on that line, and a problem the static checks already report is dropped.

Needs the optional package: pip install "goldeneye-check[ai]" (Python 3.10 or newer).
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from .i18n import LANGS
from .methodology import CATEGORIES, iso_for
from .model import Finding

DEFAULT_MODEL = "claude-opus-5-5"
BATCH_CHARS = 60_000
DOC_CHARS = 40_000
# dollars per million tokens: input, output (cache writes cost 1.25x input, cache reads 0.1x)
PRICES = {"claude-opus-5-5": (4.0, 20.0), "claude-sonnet-5-5": (2.0, 10.0), "claude-haiku-5-5": (0.10, 0.50),
          "claude-fable-5-2": (8.0, 40.0)}
KINDS = ("access_control", "info_before_auth", "secret_channel", "race_condition", "business_rule")
DEFAULT_CATEGORY = {"access_control": "D", "info_before_auth": "D", "secret_channel": "F",
                    "race_condition": "H", "business_rule": "E"}

TRI = {"type": "object", "properties": {lang: {"type": "string"} for lang in LANGS},
       "required": list(LANGS), "additionalProperties": False}
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {"findings": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": list(KINDS)},
            "category": {"type": "string", "enum": list(CATEGORIES)},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "evidence": {"type": "string"},
            "cwe": {"type": "string"},
            "title": TRI,
            "fix": TRI,
        },
        "required": ["kind", "category", "severity", "confidence", "file", "line", "evidence", "cwe", "title", "fix"],
        "additionalProperties": False}}},
    "required": ["findings"], "additionalProperties": False}
CLAIMS_SCHEMA = {
    "type": "object",
    "properties": {"claims": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "quote": {"type": "string"},
            "category": {"type": "string", "enum": list(CATEGORIES)},
            "status": {"type": "string", "enum": ["implemented", "flawed", "missing"]},
            "reason": TRI,
        },
        "required": ["file", "line", "quote", "category", "status", "reason"],
        "additionalProperties": False}}},
    "required": ["claims"], "additionalProperties": False}


@dataclass
class Payload:
    context: str
    batches: list                                   # (route names, text)
    docs: str
    sent: dict = field(default_factory=dict)        # file -> {line number: sent text}
    skipped: list = field(default_factory=list)     # routes over the budget
    routes: int = 0
    route_of: dict = field(default_factory=dict)    # (file, line) -> route name, for the route handler lines

    @property
    def chars(self) -> int:
        return len(self.context) + sum(len(t) for _n, t in self.batches) + len(self.docs)

    @property
    def lines(self) -> int:
        return sum(len(v) for v in self.sent.values())


KEYLIKE = re.compile(r"""(['"`])([A-Za-z0-9+/=_\-.]{24,})\1""")
MASK = "•••"


def secret_values(ctx) -> set:
    """Values to hide: literals that secrets fall back to in code and compose, as the static checks found them."""
    from .stages.code_defaults import _compose_literals, check_fallbacks
    _findings, literals = check_fallbacks(ctx)
    values = set(literals) | set(_compose_literals(ctx))
    return {v for v in values if len(v) >= 4}


def mask_line(text: str, values: set) -> str:
    for v in sorted(values, key=len, reverse=True):
        text = text.replace(v, MASK)
    # strings that look like keys: long, letters and digits together
    return KEYLIKE.sub(lambda m: m.group(1) + MASK + m.group(1)
                       if re.search(r"\d", m.group(2)) and re.search(r"[A-Za-z]", m.group(2)) else m.group(0), text)


def _numbered(sources, rel, start, end, values, sent) -> str:
    lines = sources.text(rel).split("\n")
    out = []
    for i in range(max(1, start), min(end, len(lines)) + 1):
        text = mask_line(lines[i - 1], values)
        sent.setdefault(rel, {})[i] = text
        out.append(f"{i:5}| {text}")
    return "\n".join(out)


def build_payload(ctx, sources, cells, findings, measures, docs, budget_chars: int = 400_000) -> Payload:
    """What is sent to the model: the summary of the static checks, the route code, the documentation."""
    from .stages.routes import CALL, KEYWORDS, Functions

    values = secret_values(ctx)
    cats = "\n".join(f"{c}: {info['name']}" for c, info in CATEGORIES.items())
    route_rows = "\n".join(
        f"- {c.route.method} {c.route.name} ({c.route.file}:{c.route.line}) signed_in={c.signed_in} admin={c.admin} "
        f"changes_data={c.mutates} csrf={c.csrf} owner_check={c.owner} audit_log={c.audit} no_store={c.no_store}"
        for c in cells)
    static = "\n".join(f"- {f.rule.rsplit('.', 1)[-1]} {f.severity} {f.file}:{f.line or ''} {f.text('title', 'en')}"
                       for f in findings)
    found = "\n".join(f"- {m.key} {m.file}: {', '.join(map(str, m.lines[:12]))}" for m in measures)
    langs = ", ".join(f"{k} ({v} files)" for k, v in sorted(ctx.languages.items()))
    images = ", ".join(sorted({c.image for c in ctx.containers if c.image}))
    context = (f"# Project\nLanguages: {langs or 'unknown'}\nImages: {images or 'none'}\n\n"
               f"# Categories A-O\n{cats}\n\n# Routes and measures (static checks)\n{route_rows or '- none found'}\n\n"
               f"# Static findings\n{static or '- none'}\n\n# Confirmed measures\n{found or '- none'}\n")

    funcs = Functions(sources)
    payload = Payload(context=context, batches=[], docs="")
    used = len(context)
    batch_names, batch_ranges, batch_size = [], [], 0

    def flush():
        nonlocal batch_names, batch_ranges, batch_size
        if not batch_names:
            return
        merged = {}
        for rel, s, e in batch_ranges:
            merged.setdefault(rel, []).append((s, e))
        parts = [f"Routes in this part: {', '.join(batch_names)}\n"]
        for rel in sorted(merged):
            ranges = sorted(merged[rel])
            joined = []
            for s, e in ranges:
                if joined and s <= joined[-1][1] + 1:
                    joined[-1] = (joined[-1][0], max(joined[-1][1], e))
                else:
                    joined.append((s, e))
            for s, e in joined:
                parts.append(f"## {rel} lines {s}-{e}\n{_numbered(sources, rel, s, e, values, payload.sent)}\n")
        payload.batches.append((list(batch_names), "\n".join(parts)))
        batch_names, batch_ranges, batch_size = [], [], 0

    for c in cells:
        ranges = list(c.route.body)
        for rel, s, e in c.route.body:
            for i in range(s, e + 1):
                payload.route_of.setdefault((rel, i), c.route.name)
        body = "\n".join("\n".join(sources.clean(rel).split("\n")[s - 1:e]) for rel, s, e in ranges)
        for m in CALL.finditer(body):
            target = funcs.get(m.group(1))
            if m.group(1) not in KEYWORDS and target and target not in ranges:
                ranges.append(target)
        size = sum(len("\n".join(sources.text(rel).split("\n")[s - 1:e])) for rel, s, e in ranges)
        if used + size > budget_chars:
            payload.skipped.append(c.route.name)
            continue
        if batch_size + size > BATCH_CHARS:
            flush()
        batch_names.append(c.route.name)
        batch_ranges += ranges
        batch_size += size
        used += size
        payload.routes += 1
    flush()

    doc_parts = []
    for rel in getattr(docs, "files", []) or []:
        n = len(sources.text(rel).split("\n")) if rel in sources.ctx.files else 0
        text = _numbered(sources, rel, 1, n, values, payload.sent)
        if used + len(text) > budget_chars or len(text) > DOC_CHARS:
            payload.skipped.append(rel)
            continue
        used += len(text)
        doc_parts.append(f"## {rel}\n{text}\n")
    if doc_parts:
        known = "\n".join(f"- {c.key}: {c.file}:{c.line} {c.text}" for c in getattr(docs, "claims", []))
        payload.docs = f"# Statements recognised by the static checks\n{known or '- none'}\n\n" + "\n".join(doc_parts)
    return payload


def describe(payload: Payload, model: str) -> str:
    files = len(payload.sent)
    docs = " and the documentation" if payload.docs else ""
    return (f"AI analysis: the code of {payload.routes} routes{docs}, "
            f"{payload.lines} lines from {files} files (about {payload.chars // 1000} KB), will be sent to the model "
            f"{model} through the Anthropic API with your key. Lines that look like secrets are masked. "
            f"Nothing is sent to goldeneye.kz.")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def _evidence_ok(payload: Payload, rel: str, line: int, evidence: str) -> bool:
    lines = payload.sent.get(rel) or {}
    ev = _norm(evidence)
    if not ev or line not in lines:
        return False
    return any(ev in _norm(lines.get(n, "")) or (len(ev) > 20 and _norm(lines.get(n, "")) in ev and
                                                  len(_norm(lines.get(n, ""))) > 20)
               for n in range(line - 3, line + 4))


def _same(f, rel, line, cat, payload) -> bool:
    """The static finding already covers this place: the same category close by, or a route finding
    of the same category that lists the route this line belongs to."""
    if f.category_code != cat:
        return False
    if f.file == rel and f.line and abs(f.line - line) <= 2:
        return True
    route = payload.route_of.get((rel, line))
    if route and f.rule.startswith("ge.route."):
        listed = f.title.get("en", "").split(":", 1)[-1]
        return route in [x.strip() for x in listed.split(",")]
    return False


def _stage(severity: str) -> str:
    return {"critical": "localhost", "high": "pilot"}.get(severity, "production")


def accept_findings(items: list, payload: Payload, static: list) -> tuple:
    """Findings that point to sent code, quote it, and do not repeat a static finding."""
    out, dropped = [], 0
    for it in items:
        rel, line = str(it.get("file", "")), int(it.get("line") or 0)
        if not _evidence_ok(payload, rel, line, it.get("evidence", "")):
            dropped += 1
            continue
        cat = it.get("category") if it.get("category") in CATEGORIES else DEFAULT_CATEGORY.get(it.get("kind"), "E")
        if any(_same(f, rel, line, cat, payload) for f in static):
            dropped += 1
            continue
        kind = it.get("kind") if it.get("kind") in KINDS else "business_rule"
        severity = it.get("severity") if it.get("severity") in ("critical", "high", "medium", "low") else "medium"
        confidence = "medium" if it.get("confidence") == "high" else (it.get("confidence") or "low")
        cwe = it.get("cwe") if re.fullmatch(r"CWE-\d+", str(it.get("cwe") or "")) else None
        title = {lang: str((it.get("title") or {}).get(lang) or "") for lang in LANGS}
        fix = {lang: str((it.get("fix") or {}).get(lang) or "") for lang in LANGS}
        f = Finding(rule=f"ge.ai.{kind.replace('_', '-')}", engine="semantic", severity=severity, category="code",
                    file=rel, line=line, title=title, fix=fix, cwe=cwe, snippet=payload.sent[rel].get(line),
                    anchor=f"ai:{kind}:{_norm(it.get('evidence', ''))[:80]}", detector="semantic",
                    category_code=cat, iso=iso_for(cat), confidence=confidence,
                    effort="days" if severity in ("critical", "high") else "hours", stage=_stage(severity))
        if all(f.fingerprint() != x.fingerprint() for x in out):
            out.append(f)
    return out, dropped


def accept_claims(items: list, payload: Payload) -> list:
    out = []
    for it in items:
        rel, line = str(it.get("file", "")), int(it.get("line") or 0)
        if not _evidence_ok(payload, rel, line, it.get("quote", "")):
            continue
        out.append({"file": rel, "line": line, "text": _norm(it.get("quote", ""))[:200],
                    "category": it.get("category") if it.get("category") in CATEGORIES else "N",
                    "status": it.get("status") if it.get("status") in ("implemented", "flawed", "missing") else "flawed",
                    "reason": {lang: str((it.get("reason") or {}).get(lang) or "") for lang in LANGS}})
    return out


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read: int = 0
    cache_write: int = 0

    def add(self, u):
        self.input_tokens += getattr(u, "input_tokens", 0) or 0
        self.output_tokens += getattr(u, "output_tokens", 0) or 0
        self.cache_read += getattr(u, "cache_read_input_tokens", 0) or 0
        self.cache_write += getattr(u, "cache_creation_input_tokens", 0) or 0

    def cost(self, model: str) -> Optional[float]:
        if model not in PRICES:
            return None
        i, o = PRICES[model]
        return round((self.input_tokens * i + self.cache_write * i * 1.25 + self.cache_read * i * 0.1
                      + self.output_tokens * o) / 1_000_000, 4)


def _ask(client, model, effort, system, context, task, text, schema, usage, warnings):
    """One request; returns the parsed JSON object or None. Authentication errors stop the layer."""
    try:
        import anthropic
        auth_error, rate_error = anthropic.AuthenticationError, anthropic.RateLimitError
        status_error, conn_error = anthropic.APIStatusError, anthropic.APIConnectionError
    except ImportError:  # a test client without the SDK
        auth_error = rate_error = status_error = conn_error = type("NoSDKError", (Exception,), {})
    try:
        with client.beta.messages.stream(
            model=model,
            max_tokens=64000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=[{"type": "text", "text": system},
                    {"type": "text", "text": context, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": f"{task}\n\n{text}"}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
        ) as stream:
            message = stream.get_final_message()
    except auth_error:
        warnings.append("AI analysis: the Anthropic API key is missing or invalid. Set ANTHROPIC_API_KEY or run "
                        "ant auth login.")
        raise
    except rate_error:
        warnings.append("AI analysis: the Anthropic API rate limit was reached; part of the code was not reviewed.")
        return None
    except status_error as e:
        warnings.append(f"AI analysis: the Anthropic API returned {getattr(e, 'status_code', '?')}; "
                        "part of the code was not reviewed.")
        return None
    except conn_error:
        warnings.append("AI analysis: cannot reach the Anthropic API; part of the code was not reviewed.")
        return None
    usage.add(message.usage)
    if message.stop_reason == "refusal":
        warnings.append("AI analysis: the model declined to review part of the code.")
        return None
    if message.stop_reason == "max_tokens":
        warnings.append("AI analysis: an answer was cut by the output limit; part of the results may be missing.")
    text_block = next((b.text for b in message.content if getattr(b, "type", "") == "text"), "")
    try:
        return json.loads(text_block)
    except ValueError:
        warnings.append("AI analysis: an answer could not be read.")
        return None


def run(prompts: dict, payload: Payload, static: list, warnings: list, model: str = None, client=None) -> dict:
    """Calls the model and returns accepted findings, claims and the usage summary."""
    model = model or prompts.get("model") or DEFAULT_MODEL
    effort = prompts.get("effort") or "high"
    if client is None:
        import anthropic
        client = anthropic.Anthropic()
    usage = Usage()
    findings, claims, dropped, failed = [], [], 0, False
    try:
        for _names, text in payload.batches:
            data = _ask(client, model, effort, prompts["system"], payload.context, prompts["routes_task"], text,
                        FINDINGS_SCHEMA, usage, warnings)
            if data:
                accepted, n = accept_findings(data.get("findings", []), payload, static + findings)
                findings += accepted
                dropped += n
        if payload.docs:
            data = _ask(client, model, effort, prompts["system"], payload.context, prompts["docs_task"], payload.docs,
                        CLAIMS_SCHEMA, usage, warnings)
            if data:
                claims = accept_claims(data.get("claims", []), payload)
    except Exception as exc:  # an authentication error stops the layer; the static report is still written
        failed = True
        if "authentication" in str(exc).lower() or "api_key" in str(exc).lower():
            if not any("API key" in w for w in warnings):
                warnings.append("AI analysis: no Anthropic API credentials. Set ANTHROPIC_API_KEY or run "
                                "ant auth login. Nothing was sent.")
        elif not any(w.startswith("AI analysis") for w in warnings):
            warnings.append(f"AI analysis failed: {str(exc)[:200]}")
    return {"findings": findings, "claims": claims, "dropped": dropped, "model": model,
            "usage": usage, "cost_usd": usage.cost(model), "failed": failed}


def dry_run(payload: Payload, prompts: dict) -> str:
    """The exact text that would be sent, for review before agreeing to send it."""
    parts = ["# System instructions\n", prompts.get("system", ""), "\n\n# Context\n", payload.context]
    for names, text in payload.batches:
        parts += ["\n\n# Request: routes ", ", ".join(names), "\n", prompts.get("routes_task", ""), "\n\n", text]
    if payload.docs:
        parts += ["\n\n# Request: documentation\n", prompts.get("docs_task", ""), "\n\n", payload.docs]
    return "".join(parts)
