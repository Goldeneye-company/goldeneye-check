"""Stage 3, the system and threat model (a light STRIDE): assets, subjects, entry points, trust boundaries.

Assets come from the database schema (tables with passwords, tokens, documents, logs), entry points
from the routes with the route x measure matrix, trust boundaries from compose and the findings
of stage 5. The model goes to the JSON report; the report shows it in step 4.
"""

import re

from .. import kb
from .absence import UPLOAD_STORE
from .context import Context
from .measures import Sources

CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`]?(\w+)[\"`]?\s*\(", re.I)
SENSITIVE_COLUMN = re.compile(r"^\s*[\"`]?(\w*(password|passwd|token|secret|hash|key|email|phone|ip_address|iin|"
                              r"passport|card|salary|birth)\w*)[\"`]?\s", re.I)
PROXIES = ("caddy", "nginx", "traefik", "haproxy", "envoy", "httpd")
DATABASES = ("postgres", "mysql", "mariadb", "mongo", "redis")


def _assets(sources: Sources) -> list:
    out = []
    for rel in sources.code + sources.other:
        text = sources.clean(rel)
        for m in CREATE_TABLE.finditer(text):
            depth, i = 1, m.end()
            while i < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[i], 0)
                i += 1
            columns = [c.group(1) for line in text[m.end():i].split(",")
                       for c in [SENSITIVE_COLUMN.match(line.strip("\n"))] if c]
            name = m.group(1)
            kind = "credentials" if any(re.search(r"pass|hash|secret|token", c, re.I) for c in columns) else \
                "documents" if re.search(r"document|file|upload|attachment", name, re.I) else \
                "log" if re.search(r"log|audit|event|history|attempt", name, re.I) else "data"
            out.append({"table": name, "kind": kind, "sensitive_columns": columns, "file": rel,
                        "line": text[:m.start()].count("\n") + 1})
    return out


def build(ctx: Context, sources: Sources, cells: list, candidates: list) -> dict:
    rules = {f.rule.rsplit(".", 1)[-1] for f in candidates}
    images = [(c.name, (c.stage.image if c.stage else c.image) or "") for c in ctx.containers]
    proxy = [n for n, img in images if any(p in img.lower() for p in PROXIES)]
    dbs = [n for n, img in images if any(d in img.lower() for d in DATABASES)
           or any(e["runtime"] in DATABASES for e in kb.entries_for(img))]
    subjects = ["anonymous"] if any(not c.signed_in for c in cells) else []
    if any(c.signed_in for c in cells):
        subjects.append("user")
    if any(c.admin for c in cells):
        subjects.append("administrator")
    if any(not c.signed_in and re.search(r"token|link|share|file", c.text, re.I) and c.sensitive for c in cells):
        subjects.append("link recipient")
    subjects += ["network attacker", "insider"]
    boundaries = [
        {"between": ["browser", "web server"], "tls": "no-tls" not in rules, "proxy": proxy},
    ]
    if dbs:
        boundaries.append({"between": ["application", "database"], "services": dbs,
                           "superuser": "db-superuser" in rules})
    if sources.find(UPLOAD_STORE) or any(c.sensitive for c in cells):
        boundaries.append({"between": ["application", "file system"]})
    return {
        "assets": _assets(sources),
        "subjects": subjects,
        "entry_points": [c.to_json() for c in cells],
        "trust_boundaries": boundaries,
    }
