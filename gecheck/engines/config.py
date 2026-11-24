"""Methodology checks that need the project context: implicit configuration (stage 5)
and the configuration and default-secret checks of stage 4."""

from pathlib import Path

from ..stages import code_defaults, context, defaults, runtimes


def scan(root: Path, warnings: list):
    ctx = context.build(root)
    return defaults.scan(ctx) + runtimes.scan(ctx) + code_defaults.scan(ctx)
