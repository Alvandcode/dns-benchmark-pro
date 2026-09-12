"""CSV / JSON exporters. No import-time side effects."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def _ensure_parent(file: Path) -> Path:
    file = Path(file)
    file.parent.mkdir(parents=True, exist_ok=True)
    return file


def export_csv(data, path="results/result.csv"):
    if not data:
        raise ValueError("no data to export (empty result list)")
    file = _ensure_parent(Path(path))
    with open(file, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
        w.writeheader()
        for row in data:
            w.writerow(row)
    return file


def export_json(data, path="results/result.json"):
    if not data:
        raise ValueError("no data to export (empty result list)")
    file = _ensure_parent(Path(path))
    file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return file
