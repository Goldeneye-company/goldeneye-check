"""Stage 5, implicit configuration, and the configuration checks of stage 4 (categories A, C, I, M).

For each container: take the defaults of its image from the KB, apply the configuration files
that the Dockerfile copies into the configuration folders and the ini_set calls in the code,
and check the effective values.
"""

import re
from pathlib import Path

from .. import kb
from ..config import ini, yamlish
from .context import Context, _read
from .findings import make

SECRET_VAR = re.compile(r"(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE|CREDENTIAL|ACCESS_KEY|DSN|DATABASE_URL)", re.I)
PLACEHOLDER = re.compile(r"^(changethis|change[-_]?me|your[-_ ].*|<.*>|x{3,}|\*+|example.*|dummy.*|todo|replace[-_].*)$", re.I)
DEFAULT_REF = re.compile(r"\$\{(\w+):?-([^}]*)\}")
INI_SET = re.compile(r"""ini_set\(\s*['"]([\w.]+)['"]\s*,\s*['"]?([^'")]*)['"]?\s*\)""")
DB_USER_KEYS = re.compile(r"^(DB_USER(NAME)?|DATABASE_USER(NAME)?|PGUSER|POSTGRES_USER|MYSQL_USER|DB_LOGIN)$", re.I)


def _php_files(ctx: Context):
    for rel in ctx.files:
        if rel.endswith(".php"):
            yield rel, _read(ctx.root / rel)


def _env(service) -> dict:
    """Environment of a compose service: name -> (raw value, line)."""
    out = {}
    node = yamlish.get(service, "environment")
    if isinstance(node, yamlish.Map):
        for k, v in node.items():
            out[k] = (yamlish.text(v) or "", node.lines.get(k))
    elif isinstance(node, yamlish.Seq):
        for item in node:
            value = yamlish.text(item) or ""
            if "=" in value:
                k, v = value.split("=", 1)
                out[k.strip()] = (v, item.line)
    return out


def _resolve(raw: str):
    """'${DB_USER:-ghalam}' -> ('DB_USER', 'ghalam'); a literal -> (None, literal)."""
    m = DEFAULT_REF.fullmatch(raw.strip())
    if m:
        return m.group(1), m.group(2)
    m = re.fullmatch(r"\$\{?(\w+)\}?", raw.strip())
    if m:
        return m.group(1), ""
    return None, raw.strip()


# Category A: secrets with a default value in compose

def check_compose_secrets(ctx: Context) -> list:
    out = []
    for rel, node, text in ctx.composes:
        for i, line in enumerate(text.splitlines(), 1):
            for m in DEFAULT_REF.finditer(line):
                var, value = m.group(1), m.group(2).strip().strip("\"'")
                if not value or not SECRET_VAR.search(var):
                    continue
                severity = "medium" if PLACEHOLDER.match(value) else "high"
                out.append(make("compose_default_secret", severity, rel, i, anchor=var, var=var))
    return out


# Stage 5 for PHP images

def php_effective(ctx: Context, container) -> dict:
    """Effective PHP settings: KB defaults, production ini, copied ini files, ini_set in code."""
    entries = kb.entries_for(container.image)
    php = next((e for e in entries if e["id"] == "php"), None)
    if not php:
        return {}
    eff = {k: (v, "image") for k, v in php["settings"].items()}
    stage = container.stage
    if stage is not None:
        prod = php["production_ini"]
        for ins in stage.instructions:
            if ins.name == "RUN" and prod["file"] in ins.args and "php.ini" in ins.args:
                eff.update({k: (v, "production ini") for k, v in prod["settings"].items()})
        from ..config import dockerfile
        for src, dest, _line in dockerfile.copies(stage):
            # the official images set ENV PHP_INI_DIR, and Dockerfiles often copy to "$PHP_INI_DIR/conf.d/"
            dest = re.sub(r"\$\{?PHP_INI_DIR\}?", php["ini_dir"], dest.strip("\"'"))
            if not dest.startswith(php["ini_dir"]) or container.context is None:
                continue
            path = (container.context / src).resolve()
            files = sorted(path.glob("*.ini")) if path.is_dir() else [path]
            for f in files:
                if f.is_file():
                    for key, (value, _n) in ini.parse(_read(f)).items():
                        eff[key] = (value, "ini")
    for _rel, code in _php_files(ctx):
        for m in INI_SET.finditer(code):
            eff[m.group(1).lower()] = (m.group(2), "ini_set")
    return eff


def _first(ctx: Context, pattern: re.Pattern):
    for rel, code in sorted(_php_files(ctx)):
        for i, line in enumerate(code.splitlines(), 1):
            if pattern.search(line):
                return rel, i
    return None


def check_php(ctx: Context) -> list:
    out, seen = [], set()
    for c in ctx.containers:
        eff = php_effective(ctx, c)
        if not eff or c.image_file in seen:
            continue
        seen.add(c.image_file)
        where = (c.image_file, c.image_line)
        if ini.truthy(eff.get("display_errors", ("0",))[0]):
            out.append(make("php_display_errors", "high", *where, anchor="display_errors", image=c.image))
        if ini.truthy(eff.get("expose_php", ("0",))[0]):
            out.append(make("php_expose", "low", *where, anchor="expose_php", image=c.image))
        if not ini.truthy(eff.get("session.use_strict_mode", ("0",))[0]):
            hit = _first(ctx, re.compile(r"\bsession_start\s*\("))
            if hit:
                out.append(make("php_session_strict", "medium", *hit, anchor="use_strict_mode"))
        php_tz, origin = eff.get("date.timezone", ("UTC", "image"))
        explicit = origin != "image" or _first(ctx, re.compile(r"date_default_timezone_set\s*\("))
        db_tz = _db_timezone(ctx)
        differ = db_tz is not None and _tz(php_tz) != _tz(db_tz)
        # Both sides on their implicit UTC defaults: correct today, breaks when either zone is set (low).
        # Zones that differ: links and tokens expire at the wrong time now (medium).
        if differ or not explicit:
            for rel, code in sorted(_php_files(ctx)):
                for i, line in enumerate(code.splitlines(), 1):
                    if re.search(r"""\bdate\(\s*['"]Y-m-d[ T]H:i""", line):
                        out.append(make("php_timezone", "medium" if differ else "low", rel, i,
                                        anchor=f"date:{i}", php_tz=php_tz or "UTC", db_tz=db_tz or "?"))
    return out


def _config_sources(ctx: Context, container):
    """Files that end up in the container: copied by the Dockerfile or mounted by compose volumes."""
    from ..config import dockerfile
    if container.stage is not None and container.context is not None:
        for src, _dest, _line in dockerfile.copies(container.stage):
            yield container.context / src
    volumes = yamlish.get(container.service, "volumes") if container.service is not None else None
    if isinstance(volumes, yamlish.Seq) and container.compose_file:
        base = (ctx.root / container.compose_file).parent
        for item in volumes:
            src = (yamlish.text(item) or "").split(":")[0]
            if src.startswith((".", "/")):
                yield base / src


def _sets(ctx: Context, container, directive: str, pattern=None) -> bool:
    """True if the image or its mounted configuration sets the directive."""
    pattern = pattern or re.compile(rf"^\s*{directive}\b", re.M | re.I)
    if container.stage is not None and any(directive in ins.args for ins in container.stage.instructions):
        return True
    for path in _config_sources(ctx, container):
        try:
            files = list(path.rglob("*")) if path.is_dir() else [path]
        except OSError:
            continue
        if any(f.is_file() and pattern.search(_read(f)) for f in files):
            return True
    return False


def check_web_servers(ctx: Context) -> list:
    """Apache and nginx images that report their version (ServerTokens, server_tokens not set)."""
    out, seen = [], set()
    for c in ctx.containers:
        image = c.stage.image if c.stage else c.image
        for e in kb.entries_for(image):
            directive = {"apache": "ServerTokens", "nginx": "server_tokens"}.get(e["runtime"])
            if not directive or (c.image_file, directive) in seen or _sets(ctx, c, directive):
                continue
            seen.add((c.image_file, directive))
            out.append(make("server_tokens", "low", c.image_file, c.image_line, anchor=directive,
                            tokens=f"{directive} {e['settings'].get(directive, 'on')}"))
    return out


def _tz(name: str) -> str:
    name = (name or "UTC").strip().upper()
    return "UTC" if name in ("UTC", "ETC/UTC", "Z", "GMT", "ETC/GMT", "UCT") else name


def _db_timezone(ctx: Context):
    """Time zone of the PostgreSQL service: TZ, PGTZ or -c timezone=, otherwise the image default (UTC)."""
    for c in ctx.containers:
        if c.service is None or not any(e["runtime"] == "postgres" for e in kb.entries_for(c.image)):
            continue
        env = _env(c.service)
        for key in ("PGTZ", "TZ"):
            if key in env and env[key][0]:
                return _resolve(env[key][0])[1] or "UTC"
        command = yamlish.text(c.service.get("command")) or ""
        m = re.search(r"timezone\s*=\s*['\"]?([\w/+-]+)", command, re.I)
        return m.group(1) if m else "UTC"
    return None


# Category M: database superuser

def check_db_superuser(ctx: Context) -> list:
    out = []
    for c in ctx.containers:
        if c.service is None:
            continue
        for e in kb.entries_for(c.image if not c.stage else c.stage.image):
            if e["runtime"] not in ("postgres", "mysql"):
                continue
            env = _env(c.service)
            if e["runtime"] == "postgres":
                raw, line = env.get(e["settings"]["user_env"], (e["settings"]["default_user"], None))
                super_token = _resolve(raw)
            else:
                super_token, line = (None, "root"), env.get("MYSQL_ROOT_PASSWORD", ("", None))[1]
            for other in ctx.containers:
                if other is c or other.service is None or other.compose_file != c.compose_file:
                    continue
                for key, (value, _l) in _env(other.service).items():
                    if not DB_USER_KEYS.match(key) or key == e["settings"].get("user_env"):
                        continue
                    token = _resolve(value)
                    same = (token[0] and token[0] == super_token[0]) or (token[1] and token[1] == super_token[1])
                    if same:
                        out.append(make("db_superuser", "high", c.compose_file,
                                        line or c.service.line, anchor=f"{other.name}->{c.name}",
                                        app=other.name, db=c.name))
    return out


# Category C: plain HTTP published without a TLS terminator

PORT = re.compile(r"^(?:(?P<ip>\d+\.\d+\.\d+\.\d+|\[[^\]]+\]|localhost):)?(?:(?P<host>\d+)(?:-\d+)?:)?(?P<cont>\d+)(?:/(?:tcp|udp))?$")


def _ports(service):
    node = yamlish.get(service, "ports")
    if not isinstance(node, yamlish.Seq):
        return
    for item in node:
        value = yamlish.text(item)
        if value is None and isinstance(item, yamlish.Map):  # long syntax
            value = f"{yamlish.text(item.get('host_ip')) + ':' if item.get('host_ip') else ''}" \
                    f"{yamlish.text(item.get('published')) or ''}:{yamlish.text(item.get('target')) or ''}"
        m = PORT.match((value or "").strip())
        if m:
            yield m.group("ip"), m.group("host"), int(m.group("cont")), item.line


def check_tls(ctx: Context) -> list:
    out = []
    data = kb.load()
    for rel, node, _text in ctx.composes:
        containers = [c for c in ctx.containers if c.compose_file == rel]
        terminated = False
        for c in containers:
            image = (c.stage.image if c.stage else c.image).lower()
            if any(t in image for t in data["tls_terminators"]) or any(
                    cont == 443 for _ip, _h, cont, _l in _ports(c.service)):
                terminated = True
        if terminated:
            continue
        for c in containers:
            for ip, host, cont, line in _ports(c.service):
                if ip in ("127.0.0.1", "[::1]", "localhost"):
                    continue
                if cont in data["web_ports"] or (host and int(host) in data["web_ports"]):
                    out.append(make("no_tls", "high", rel, line, anchor=f"{c.name}:{cont}",
                                    service=c.name, port=host or cont))
    return out


# Category M: container hardening and image pinning

def check_hardening(ctx: Context) -> list:
    out, pinned_seen = [], set()
    for c in ctx.containers:
        if c.service is not None:
            svc = c.service
            missing = []
            if yamlish.text(svc.get("read_only")) not in ("true", "True"):
                missing.append("read_only: true")
            cap = svc.get("cap_drop")
            if not (isinstance(cap, yamlish.Seq) and any(yamlish.text(x) in ("ALL", "all") for x in cap)):
                missing.append("cap_drop: [ALL]")
            sec = svc.get("security_opt")
            if not (isinstance(sec, yamlish.Seq) and any("no-new-privileges" in (yamlish.text(x) or "") for x in sec)):
                missing.append("security_opt: [no-new-privileges:true]")
            if not (svc.get("mem_limit") or svc.get("cpus") or yamlish.get(svc, "deploy", "resources", "limits")):
                missing.append("deploy.resources.limits")
            if c.stage is not None and not any(i.name == "USER" for i in c.stage.instructions) \
                    and not svc.get("user"):
                if any(e.get("user") == "root" for e in kb.entries_for(c.stage.image)):
                    missing.append("USER")
            if len(missing) >= 3:
                parent = c.compose_text and yamlish.get(yamlish.parse(c.compose_text), "services")
                line = parent.lines.get(c.name) if isinstance(parent, yamlish.Map) else svc.line
                out.append(make("container_hardening", "medium", c.compose_file, line, anchor=c.name,
                                service=c.name, missing=", ".join(missing)))
        ref = c.image
        key = (c.image_file, ref)
        if ref and "@sha256:" not in ref and key not in pinned_seen and not ref.startswith("$"):
            pinned_seen.add(key)
            # an image built from a stage of the same Dockerfile is not a pull
            out.append(make("image_unpinned", "low", c.image_file, c.image_line, anchor=ref, image=ref))
    return out


def scan(ctx: Context) -> list:
    findings = []
    for check in (check_compose_secrets, check_php, check_web_servers, check_db_superuser, check_tls,
                  check_hardening):
        findings += check(ctx)
    return findings
