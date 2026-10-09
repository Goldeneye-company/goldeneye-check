import subprocess
from pathlib import Path

from ..install import engine_path


class EngineMissing(Exception):
    pass


def run_engine(name: str, args, cwd=None, timeout=900) -> subprocess.CompletedProcess:
    exe = engine_path(name)
    if not exe.exists():
        raise EngineMissing(name)
    return subprocess.run([str(exe), *args], cwd=cwd, capture_output=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def rel_path(root: Path, path: str) -> str:
    """Путь относительно корня проекта, всегда через «/»: так отчёт одинаков на Windows и Linux."""
    p = Path(path)
    if p.is_absolute():
        for candidate, base in ((p, root), (p.resolve(), root.resolve())):
            try:
                p = candidate.relative_to(base)
                break
            except ValueError:
                continue
    s = p.as_posix()
    return s[2:] if s.startswith("./") else s
