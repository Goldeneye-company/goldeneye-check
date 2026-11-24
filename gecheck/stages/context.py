"""Stage 1, context: the stack and how the project runs.

This part reads the files that describe the stack (compose, Dockerfiles, package manifests).
Purpose, declared measures and known limitations from the README come in a later version.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import dockerfile, yamlish
from ..model import SKIP_DIRS

LANG_EXT = {".php": "php", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
            ".ts": "typescript", ".tsx": "typescript", ".py": "python", ".go": "go", ".java": "java",
            ".rb": "ruby", ".cs": "csharp"}
MANIFESTS = ("composer.json", "package.json", "requirements.txt", "pyproject.toml", "go.mod", "pom.xml", "Gemfile")
COMPOSE_NAMES = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml")


@dataclass
class Container:
    """A container that runs: a compose service or a standalone Dockerfile."""
    name: str
    image: str                      # runtime image reference
    image_file: str                 # file where the image is named (Dockerfile or compose)
    image_line: Optional[int]
    stage: object = None            # final Dockerfile stage, if the image is built
    dockerfile: Optional[str] = None
    context: Optional[Path] = None  # build context folder
    service: object = None          # compose service node (yamlish.Map)
    compose_file: Optional[str] = None
    compose_text: str = ""


@dataclass
class Context:
    root: Path
    languages: dict = field(default_factory=dict)  # language -> number of files
    manifests: list = field(default_factory=list)
    composes: list = field(default_factory=list)   # (rel path, parsed node, text)
    containers: list = field(default_factory=list)
    files: list = field(default_factory=list)      # relative paths of all scanned files


def _files(root: Path):
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or p.is_symlink() or not p.is_file():
            continue
        yield p, rel.as_posix()


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore") if p.stat().st_size < 2_000_000 else ""
    except OSError:
        return ""


def _dockerfile(root: Path, path: Path):
    text = _read(path)
    stages = dockerfile.parse(text)
    return dockerfile.runtime(stages)


def build(root: Path) -> Context:
    ctx = Context(root=root)
    for p, rel in _files(root):
        ctx.files.append(rel)
        lang = LANG_EXT.get(p.suffix.lower())
        if lang:
            ctx.languages[lang] = ctx.languages.get(lang, 0) + 1
        if p.name in MANIFESTS:
            ctx.manifests.append(rel)

    used_dockerfiles = set()
    for rel in sorted(ctx.files):
        name = rel.rsplit("/", 1)[-1]
        if not any(Path(name).match(pattern) for pattern in COMPOSE_NAMES):
            continue
        text = _read(root / rel)
        try:
            node = yamlish.parse(text)
        except Exception:  # an unreadable compose file is skipped, not fatal
            continue
        ctx.composes.append((rel, node, text))
        services = yamlish.get(node, "services")
        if not isinstance(services, yamlish.Map):
            continue
        base = (root / rel).parent
        for svc_name, svc in services.items():
            if not isinstance(svc, yamlish.Map):
                continue
            image = yamlish.text(svc.get("image")) or ""
            image_line = svc.lines.get("image")
            stage = df_rel = context_dir = None
            build_node = svc.get("build")
            if build_node is not None:
                if isinstance(build_node, yamlish.Map):
                    context_dir = base / (yamlish.text(build_node.get("context")) or ".")
                    df_name = yamlish.text(build_node.get("dockerfile")) or "Dockerfile"
                else:
                    context_dir = base / (yamlish.text(build_node) or ".")
                    df_name = "Dockerfile"
                df_path = (context_dir / df_name).resolve()
                try:
                    df_rel = df_path.relative_to(root.resolve()).as_posix()
                except ValueError:
                    df_rel = None
                if df_rel and df_path.is_file():
                    used_dockerfiles.add(df_rel)
                    stage = _dockerfile(root, df_path)
                    if stage:
                        image, image_line = stage.image, stage.line
            ctx.containers.append(Container(
                name=svc_name, image=image, image_file=df_rel if stage else rel,
                image_line=image_line, stage=stage, dockerfile=df_rel if stage else None,
                context=context_dir, service=svc, compose_file=rel, compose_text=text))

    for rel in sorted(ctx.files):
        name = rel.rsplit("/", 1)[-1]
        if (name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile.")) \
                and rel not in used_dockerfiles:
            stage = _dockerfile(root, root / rel)
            if stage:
                ctx.containers.append(Container(
                    name=rel, image=stage.image, image_file=rel, image_line=stage.line, stage=stage,
                    dockerfile=rel, context=(root / rel).parent))
    return ctx
