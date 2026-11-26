"""Methodology checks that need the project context.

Stage 1 (stack), stage 2 (inventory), stage 3 (routes and the system model), stage 4 (configuration checks,
missing measures and the route x measure matrix), stage 5 (implicit configuration) and stage 7
(confirmed measures and verification of candidates).
"""

from pathlib import Path

from ..stages import (absence, code_defaults, context, defaults, inventory, matrix, measures, routes, runtimes,
                      system, verify)


def scan(root: Path, warnings: list, extras: dict = None):
    ctx = context.build(root)
    sources = measures.Sources(ctx)
    found_measures = measures.collect(ctx, sources)
    inv = inventory.build(ctx)
    cells = matrix.build(sources, routes.collect(sources), ctx)
    candidates = (defaults.scan(ctx) + runtimes.scan(ctx) + code_defaults.scan(ctx)
                  + absence.scan(ctx, sources, found_measures) + inventory.check(inv)
                  + matrix.scan(ctx, sources, cells, measures.by_key(found_measures)))
    if extras is not None:
        extras["measures"] = found_measures
        extras["inventory"] = inv
        extras["model"] = system.build(ctx, sources, cells, candidates)
    return verify.apply(candidates, sources, found_measures)
