"""Local MITRE ATT&CK catalog access."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict


@lru_cache(maxsize=1)
def load_attack_catalog() -> Dict[str, Any]:
    path = Path(__file__).with_name("data") / "attack_catalog.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["by_id"] = {
        str(item["id"]): item
        for item in (data.get("techniques") or [])
        if isinstance(item, dict) and item.get("id")
    }
    return data
