"""php.ini style files: key = value with line numbers (last value wins, as in PHP)."""

import re

_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*(.*?)\s*$")


def parse(text: str) -> dict:
    out = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in ";#[":
            continue
        m = _LINE.match(line)
        if m:
            value = m.group(2).split(";")[0].strip().strip("\"'")
            out[m.group(1).lower()] = (value, n)
    return out


def truthy(value: str) -> bool:
    return str(value).strip().lower() in ("1", "on", "true", "yes", "stdout", "stderr")
