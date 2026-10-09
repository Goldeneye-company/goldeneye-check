import os
from pathlib import Path


def home() -> Path:
    """Папка GoldenEye Check: движки и кэш. Переопределяется переменной GECHECK_HOME."""
    custom = os.environ.get("GECHECK_HOME")
    return Path(custom) if custom else Path.home() / ".goldeneye-check"


def engines_dir() -> Path:
    return home() / "engines"


RULES_DIR = Path(__file__).parent / "rules"
