"""A small YAML reader for docker-compose files, with line numbers.

Covers what compose files use: block mappings and sequences, plain and quoted scalars,
block scalars (| and >). Flow collections ([...], {...}) are kept as text.
Anchors, aliases and multiple documents are not supported: such values stay as text.
"""

import re
from typing import Optional


class Scalar:
    __slots__ = ("value", "line")

    def __init__(self, value: str, line: int):
        self.value, self.line = value, line

    def __repr__(self):
        return f"Scalar({self.value!r}, line={self.line})"


class Map(dict):
    """dict of key -> node; .lines holds the line of each key, .line the first line."""

    def __init__(self, line: int):
        super().__init__()
        self.lines, self.line = {}, line


class Seq(list):
    def __init__(self, line: int):
        super().__init__()
        self.line = line


def _strip_comment(text: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'" and (i == 0 or text[i - 1] in " \t:-[{,"):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        inner = s[1:-1]
        return inner.replace("''", "'") if s[0] == "'" else inner.replace('\\"', '"')
    return s


_KEY = re.compile(r"""^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^:#'"\s][^:#]*?)\s*:(?:\s+(.*)|$)""")


def _split_key(text: str):
    m = _KEY.match(text)
    if not m:
        return None
    return _unquote(m.group(1)), (m.group(2) or "").strip()


def parse(text: str) -> Optional[object]:
    rows = []
    raw = text.splitlines()
    for n, line in enumerate(raw, 1):
        if line.strip() in ("---", "..."):
            continue
        body = _strip_comment(line)
        if not body.strip():
            rows.append((None, "", n, line))
            continue
        indent = len(body) - len(body.lstrip(" "))
        rows.append((indent, body.strip(), n, line))
    rows_clean = [r for r in rows if r[0] is not None]
    if not rows_clean:
        return None
    node, _ = _block(rows_clean, 0, rows_clean[0][0], raw)
    return node


def _block(rows, i, indent, raw):
    if rows[i][1].startswith("- ") or rows[i][1] == "-":
        return _seq(rows, i, indent, raw)
    return _map(rows, i, indent, raw)


def _value(rows, i, indent, rest, line, raw):
    """Value after "key:" or "- ". Returns (node, next index)."""
    if rest in ("|", ">", "|-", ">-", "|+", ">+"):
        parts, j = [], i + 1
        while j < len(rows) and rows[j][0] > indent:
            parts.append(rows[j][1])
            j += 1
        sep = "\n" if rest.startswith("|") else " "
        return Scalar(sep.join(parts), line), j
    if rest:
        return Scalar(_unquote(rest), line), i + 1
    j = i + 1
    if j < len(rows) and (rows[j][0] > indent or (rows[j][0] == indent and rows[j][1].startswith("-"))):
        return _block(rows, j, rows[j][0], raw)
    return Scalar("", line), j


def _map(rows, i, indent, raw):
    node = Map(rows[i][2])
    while i < len(rows) and rows[i][0] == indent and not rows[i][1].startswith("- "):
        kv = _split_key(rows[i][1])
        if kv is None:
            i += 1
            continue
        key, rest = kv
        node.lines[key] = rows[i][2]
        node[key], i = _value(rows, i, indent, rest, rows[i][2], raw)
    return node, i


def _seq(rows, i, indent, raw):
    node = Seq(rows[i][2])
    while i < len(rows) and rows[i][0] == indent and (rows[i][1].startswith("- ") or rows[i][1] == "-"):
        item = rows[i][1][2:].strip() if rows[i][1] != "-" else ""
        line = rows[i][2]
        if item and _split_key(item) and not item.startswith(("'", '"', "[", "{")):
            # "- key: value": a mapping whose keys sit two columns to the right
            inner = indent + 2 + (len(rows[i][1][2:]) - len(rows[i][1][2:].lstrip(" ")))
            rows[i] = (inner, item, line, rows[i][3])
            value, i = _map(rows, i, inner, raw)
        else:
            value, i = _value(rows, i, indent, item, line, raw)
        node.append(value)
    return node, i


def get(node, *path):
    for key in path:
        if not isinstance(node, Map) or key not in node:
            return None
        node = node[key]
    return node


def text(node) -> Optional[str]:
    return node.value if isinstance(node, Scalar) else None
