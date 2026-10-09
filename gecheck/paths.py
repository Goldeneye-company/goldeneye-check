import os
from pathlib import Path


def home() -> Path:
    """Рабочая папка с движками; можно задать через GECHECK_HOME."""
    custom = os.environ.get("GECHECK_HOME")
    return Path(custom) if custom else Path.home() / ".goldeneye-check"


def engines_dir() -> Path:
    return home() / "engines"


RULES_DIR = Path(__file__).parent / "rules"
