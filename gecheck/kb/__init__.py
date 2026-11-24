"""Knowledge base of image and runtime defaults (methodology, stage 5)."""

import json
import re
from functools import lru_cache
from pathlib import Path

KB_FILE = Path(__file__).with_name("defaults.json")


@lru_cache(maxsize=1)
def load() -> dict:
    return json.loads(KB_FILE.read_text(encoding="utf-8"))


def entries_for(image: str) -> list:
    """All KB entries whose pattern matches the image reference (php:8.3-apache gives php and php-apache)."""
    image = (image or "").strip().lower()
    return [e for e in load()["images"] if re.search(e["match"], image)]
