"""Named benchmark presets (e.g. --preset ir)."""

from __future__ import annotations

import json
from pathlib import Path

_PRESET_DIR = Path(__file__).resolve().parent.parent / "presets"


def list_presets() -> list:
    if not _PRESET_DIR.is_dir():
        return []
    return sorted(p.stem for p in _PRESET_DIR.glob("*.json"))


def load_preset(name: str) -> dict:
    path = _PRESET_DIR / f"{name}.json"
    if not path.is_file():
        raise ValueError(
            f"unknown preset {name!r} (available: {', '.join(list_presets()) or 'none'})"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"broken preset file {path}: {exc}") from exc
    for key in ("dns", "internal_domains", "external_domains"):
        if not isinstance(data.get(key), list) or not data[key]:
            raise ValueError(f"preset {name!r} is missing a non-empty {key!r} list")
    data["domains"] = list(data["internal_domains"]) + list(data["external_domains"])
    return data
