"""Stage 5 for Java and Go: image, JVM, Spring Boot, Tomcat, Gin and net/http defaults."""

import re

from .. import kb
from ..config import yamlish
from .context import Context, _read
from .defaults import _env, _sets
from .findings import make

JDWP = re.compile(r"-agentlib:jdwp=[^\s\"']*|-Xrunjdwp:[^\s\"']*")
JMX_NO_AUTH = re.compile(r"-Dcom\.sun\.management\.jmxremote\.authenticate=false")
DEV_PROFILE = re.compile(r"application-(dev|local|test|debug)[\w-]*\.(properties|ya?ml)$", re.I)


def _startup_texts(container):
    """Text that configures the JVM at start: Dockerfile ENV/CMD/ENTRYPOINT and compose environment/command."""
    if container.stage is not None:
        for ins in container.stage.instructions:
            if ins.name in ("ENV", "CMD", "ENTRYPOINT", "RUN"):
                yield container.image_file, ins.line, ins.args
    if container.service is not None:
        for key, (value, line) in _env(container.service).items():
            yield container.compose_file, line, f"{key}={value}"
        for key in ("command", "entrypoint"):
            node = container.service.get(key)
            text = yamlish.text(node)
            if text:
                yield container.compose_file, container.service.lines.get(key), text
            elif isinstance(node, yamlish.Seq):
                yield container.compose_file, node.line, " ".join(yamlish.text(x) or "" for x in node)


def check_containers(ctx: Context) -> list:
    out = []
    for c in ctx.containers:
        image = c.stage.image if c.stage else c.image
        entries = kb.entries_for(image)
        runtimes = {e["runtime"] for e in entries}
        if "build" in runtimes:
            out.append(make("build_image_runtime", "medium", c.image_file, c.image_line, anchor=image, image=image))
        for rel, line, text in _startup_texts(c):
            if JDWP.search(text):
                out.append(make("java_debug_port", "high", rel, line, anchor=f"jdwp:{c.name}", service=c.name))
            if JMX_NO_AUTH.search(text):
                out.append(make("jmx_no_auth", "high", rel, line, anchor=f"jmx:{c.name}", service=c.name))
        if "tomcat" in runtimes:
            if c.stage is not None and any("webapps.dist" in i.args for i in c.stage.instructions):
                line = next(i.line for i in c.stage.instructions if "webapps.dist" in i.args)
                out.append(make("tomcat_manager", "medium", c.image_file, line, anchor="webapps.dist"))
            if not _sets(ctx, c, "showServerInfo", re.compile(r"showServerInfo\s*=\s*[\"']false[\"']", re.I)):
                out.append(make("server_tokens", "low", c.image_file, c.image_line, anchor="showServerInfo",
                                tokens='showServerInfo="true"'))
    return out


# Spring Boot

def _flatten(node, prefix="", out=None):
    out = {} if out is None else out
    if isinstance(node, yamlish.Map):
        for key, value in node.items():
            name = f"{prefix}.{key}" if prefix else key
            if isinstance(value, (yamlish.Map, yamlish.Seq)):
                _flatten(value, name, out)
            else:
                out[name.lower()] = (value.value, node.lines.get(key))
    elif isinstance(node, yamlish.Seq):
        out[prefix.lower()] = (",".join(yamlish.text(x) or "" for x in node), node.line)
    return out


def spring_properties(path_text: str, is_yaml: bool) -> dict:
    if is_yaml:
        try:
            return _flatten(yamlish.parse(path_text))
        except Exception:
            return {}
    out = {}
    for n, raw in enumerate(path_text.splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        m = re.match(r"([\w.\-\[\]]+)\s*[=:]\s*(.*)$", line)
        if m:
            out[m.group(1).lower()] = (m.group(2).strip(), n)
    return out


def uses_spring(ctx: Context) -> bool:
    for rel in ctx.files:
        if rel.rsplit("/", 1)[-1] in ("pom.xml", "build.gradle", "build.gradle.kts"):
            if "spring-boot" in _read(ctx.root / rel):
                return True
    return False


def check_spring(ctx: Context) -> list:
    if not uses_spring(ctx):
        return []
    fw = next(f for f in kb.load()["frameworks"] if f["id"] == "spring-boot")
    unsafe = fw["unsafe"]
    out = []
    for rel in sorted(ctx.files):
        name = rel.rsplit("/", 1)[-1]
        if not re.match(r"(application|bootstrap)[\w-]*\.(properties|ya?ml)$", name) or "/test/" in f"/{rel}":
            continue
        props = spring_properties(_read(ctx.root / rel), not name.endswith(".properties"))
        dev = bool(DEV_PROFILE.search(name))
        for key, bad in unsafe.items():
            if key not in props:
                continue
            value, line = props[key]
            values = {v.strip().lower() for v in value.split(",")}
            hit = sorted(values & {b.lower() for b in bad})
            if not hit:
                continue
            rule = {"management.endpoints.web.exposure.include": "spring_actuator_exposed",
                    "spring.h2.console.enabled": "spring_h2_console",
                    "server.error.include-stacktrace": "spring_stacktrace"}.get(key, "spring_actuator_exposed")
            severity = "low" if dev else ("medium" if rule == "spring_stacktrace" else "high")
            out.append(make(rule, severity, rel, line, anchor=key, key=key, value=", ".join(hit)))
    return out


# Go

def _go_files(ctx: Context):
    for rel in sorted(ctx.files):
        if rel.endswith(".go") and not rel.endswith("_test.go"):
            yield rel, _read(ctx.root / rel)


def _go_mod(ctx: Context) -> str:
    return "\n".join(_read(ctx.root / rel) for rel in ctx.files if rel.rsplit("/", 1)[-1] == "go.mod")


def check_go(ctx: Context) -> list:
    files = list(_go_files(ctx))
    if not files:
        return []
    out = []
    code_all = "\n".join(code for _r, code in files)

    if "github.com/gin-gonic/gin" in _go_mod(ctx) or "gin-gonic/gin" in code_all:
        release_in_code = re.search(r"gin\.SetMode\(\s*gin\.ReleaseMode\s*\)", code_all)
        release_in_env = any("GIN_MODE" in t and "release" in t
                             for c in ctx.containers for _r, _l, t in _startup_texts(c))
        if not release_in_code and not release_in_env:
            for rel, code in files:
                m = re.search(r"gin\.(Default|New)\(\)", code)
                if m:
                    out.append(make("gin_debug", "medium", rel, code.count("\n", 0, m.start()) + 1, anchor="gin"))
                    break

    default_mux = re.search(r"http\.ListenAndServe(TLS)?\([^)]*,\s*nil\s*\)", code_all)
    for rel, code in files:
        m = re.search(r"""_\s+"net/http/pprof\"""", code)
        if m:
            out.append(make("go_pprof", "high" if default_mux else "medium", rel,
                            code.count("\n", 0, m.start()) + 1, anchor="pprof"))
        for m in re.finditer(r"\bhttp\.ListenAndServe(TLS)?\(", code):
            out.append(make("go_http_timeouts", "medium", rel, code.count("\n", 0, m.start()) + 1,
                            anchor=f"listen:{m.start()}"))
        for m in re.finditer(r"&?http\.Server\s*\{", code):
            depth, j = 1, m.end()
            while j < len(code) and depth:
                depth += {"{": 1, "}": -1}.get(code[j], 0)
                j += 1
            if "ReadHeaderTimeout" not in code[m.end():j] and "ReadTimeout" not in code[m.end():j]:
                out.append(make("go_http_timeouts", "medium", rel, code.count("\n", 0, m.start()) + 1,
                                anchor=f"server:{m.start()}"))
    return out


def scan(ctx: Context) -> list:
    return check_containers(ctx) + check_spring(ctx) + check_go(ctx)
