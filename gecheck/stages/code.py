"""Structure of brace languages (PHP, JavaScript, TypeScript, Java, Go): which block a line belongs to.

Strings, comments and PHP heredocs are masked before braces are counted, so a brace in a string
or in SQL text does not shift the blocks. The result is approximate, but it is enough to tell
"the code of this route or function" from "the rest of the file".
"""

import re
from dataclasses import dataclass, field
from typing import Optional

CLASS_HEADER = re.compile(r"\b(class|interface|trait|enum|namespace)\b")
FUNC_NAME = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(|\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\(")
CONTROL = re.compile(r"^\s*(?:\}\s*)?(if|else|elseif|for|foreach|while|switch|catch|try|do|finally|match)\b")
LANG_BY_EXT = {".php": "php", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
               ".java": "java", ".go": "go", ".cs": "java", ".kt": "java"}


@dataclass
class Block:
    start: int                 # line of the opening brace (1-based)
    end: int                   # line of the closing brace
    header: str                # code between the previous statement and the brace
    parent: Optional["Block"] = None
    children: list = field(default_factory=list)

    @property
    def is_function(self) -> bool:
        h = self.header.strip()
        if FUNC_NAME.search(h) or re.search(r"\bfunction\b\s*\(", h) or h.endswith("=>"):
            return True
        if CLASS_HEADER.search(h) or CONTROL.match(h):
            return False
        # a method: name(args) or name(args): type / throws X
        return bool(re.search(r"\w\s*\([^()]*(\([^()]*\)[^()]*)*\)\s*(:\s*[\w?|\\<>\[\], ]+|throws [\w., ]+)?$", h))

    @property
    def is_class(self) -> bool:
        return bool(CLASS_HEADER.search(self.header)) and not FUNC_NAME.search(self.header)

    @property
    def name(self) -> Optional[str]:
        m = FUNC_NAME.search(self.header)
        if m:
            return m.group(1) or m.group(2)
        m = re.search(r"(\w+)\s*\([^()]*\)\s*(:[^{]*)?$", self.header.strip())
        return m.group(1) if m and self.is_function else None


def mask(code: str, lang: str = "php", keep_strings: bool = False) -> str:
    """Replaces the contents of strings and comments with spaces, keeps the line breaks.

    With keep_strings only comments are removed: SQL and header values stay searchable.
    """
    out, i, n = [], 0, len(code)
    hash_comment = lang in ("php", "python")
    if lang in ("python", "shell", "config"):
        return "\n".join(_strip_hash_comment(line) for line in code.split("\n"))
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if (c == "/" and nxt == "/") or (c == "#" and hash_comment and nxt != "["):
            j = code.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and nxt == "*":
            j = code.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", code[i:j]))
            i = j
        elif lang == "php" and code.startswith("<<<", i):
            m = re.match(r"<<<\s*['\"]?(\w+)['\"]?", code[i:])
            body = code.find("\n", i)
            if not m or body < 0:
                out.append(c)
                i += 1
                continue
            em = re.compile(r"^[ \t]*" + re.escape(m.group(1)) + r"\b", re.M).search(code, body + 1)
            j = em.end() if em else n
            out.append(code[i:j] if keep_strings else re.sub(r"[^\n]", " ", code[i:j]))
            i = j
        elif c in "'\"`":
            j = i + 1
            while j < n and code[j] != c:
                if code[j] == "\\":
                    j += 1
                elif code[j] == "\n" and c != "`" and lang != "php":
                    break
                j += 1
            j = min(j + 1, n)
            if keep_strings:
                out.append(code[i:j])
            else:
                out.append(c + re.sub(r"[^\n]", " ", code[i + 1:j - 1]) + (code[j - 1] if j - 1 > i else ""))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _strip_hash_comment(line: str) -> str:
    """Removes a # or ; comment that is not inside quotes (Python, shell, ini, compose)."""
    if line.lstrip().startswith((";", "#")):
        return ""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


class Structure:
    """Blocks of one file. Line numbers are 1-based."""

    def __init__(self, code: str, lang: str = "php"):
        self.lines = code.splitlines()
        masked = mask(code, lang)
        self.masked_lines = masked.splitlines()
        self.blocks = []
        stack, line, last_break = [], 1, 0
        for pos, ch in enumerate(masked):
            if ch == "\n":
                line += 1
            elif ch == "{":
                header = " ".join(masked[last_break:pos].split())
                b = Block(start=line, end=line, header=header[-300:], parent=stack[-1] if stack else None)
                if stack:
                    stack[-1].children.append(b)
                self.blocks.append(b)
                stack.append(b)
                last_break = pos + 1
            elif ch == "}":
                if stack:
                    stack.pop().end = line
                last_break = pos + 1
            elif ch == ";":
                last_break = pos + 1
        for b in stack:
            b.end = line

    def _around(self, line: int) -> list:
        return [b for b in self.blocks if b.start <= line <= b.end]

    def unit(self, line: int) -> Optional[Block]:
        """The function that contains the line; otherwise the outermost block; None at the top level."""
        blocks = self._around(line)
        for b in reversed(blocks):
            if b.is_function:
                return b
        tops = [b for b in blocks if not b.is_class]
        return tops[0] if tops else None

    def in_function(self, line: int) -> bool:
        return any(b.is_function for b in self._around(line))

    def always_runs(self, line: int) -> bool:
        """Top-level code outside functions and outside if/else/switch/catch: it runs whenever the file runs."""
        for b in self._around(line):
            if b.is_function or b.is_class:
                return False
            if re.match(r"^\s*(?:\}\s*)?(if|else|elseif|switch|catch|match|case)\b", b.header):
                return False
        return True

    def text(self, start: int, end: int) -> str:
        return "\n".join(self.lines[max(0, start - 1):end])

    def unit_range(self, line: int) -> tuple:
        u = self.unit(line)
        return (u.start, u.end) if u else (1, len(self.lines))

    def unit_text(self, line: int, before_only: bool = False) -> str:
        """Code of the unit around the line (the whole file at the top level); up to the line if before_only."""
        start, end = self.unit_range(line)
        return self.text(start, line if before_only else end)

    def functions(self) -> dict:
        """Function name -> block."""
        return {b.name: b for b in self.blocks if b.is_function and b.name}
