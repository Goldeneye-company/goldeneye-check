"""Methodology checks that need the project context.

Stage 1 (stack), stage 2 (inventory), stage 4 (configuration checks and missing measures),
stage 5 (implicit configuration) and stage 7 (confirmed measures and verification of candidates).
"""

from pathlib import Path

from ..stages import absence, code_defaults, context, defaults, inventory, measures, runtimes, verify


def scan(root: Path, warnings: list, extras: dict = None):
    ctx = context.build(root)
    sources = measures.Sources(ctx)
    found_measures = measures.collect(ctx, sources)
    inv = inventory.build(ctx)
    candidates = (defaults.scan(ctx) + runtimes.scan(ctx) + code_defaults.scan(ctx)
                  + absence.scan(ctx, sources, found_measures) + inventory.check(inv))
    if extras is not None:
        extras["measures"] = found_measures
        extras["inventory"] = inv
    return verify.apply(candidates, sources, found_measures)
