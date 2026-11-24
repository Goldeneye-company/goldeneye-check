"""Dockerfile reader: instructions with their line numbers; only the final stage matters for runtime."""

import re
import shlex
from dataclasses import dataclass, field


@dataclass
class Instruction:
    name: str
    args: str
    line: int


@dataclass
class Stage:
    image: str
    line: int
    alias: str = ""
    instructions: list = field(default_factory=list)


def parse(text: str) -> list:
    """Returns the build stages; the last one is the image that runs."""
    stages, buf, start = [], "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        m = re.match(r"(\w+)\s*(.*)", buf, re.S)
        buf = ""
        if not m:
            continue
        name, args = m.group(1).upper(), m.group(2).strip()
        if name == "FROM":
            parts = [p for p in args.split() if not p.startswith("--")]
            image = parts[0] if parts else ""
            alias = parts[2] if len(parts) >= 3 and parts[1].lower() == "as" else ""
            stages.append(Stage(image=image, line=start, alias=alias))
        elif stages:
            stages[-1].instructions.append(Instruction(name, args, start))
    return stages


def copies(stage: Stage) -> list:
    """(source, destination, line) for COPY/ADD from the build context (not --from other stages)."""
    out = []
    for ins in stage.instructions:
        if ins.name not in ("COPY", "ADD"):
            continue
        args = ins.args
        if args.startswith("["):
            try:
                import json
                parts = json.loads(args)
            except ValueError:
                continue
        else:
            try:
                parts = shlex.split(args)
            except ValueError:
                parts = args.split()
        if any(p.startswith("--from") for p in parts):
            continue
        parts = [p for p in parts if not p.startswith("--")]
        if len(parts) >= 2:
            for src in parts[:-1]:
                out.append((src, parts[-1], ins.line))
    return out


def runtime(stages: list):
    return stages[-1] if stages else None
