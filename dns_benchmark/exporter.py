import csv
import json
from pathlib import Path

Path("results").mkdir(exist_ok=True)


def export_csv(data):

    file = Path("results/result.csv")

    with open(file, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(data[0].keys())
        for r in data:
            w.writerow(r.values())

    return file


def export_json(data):

    file = Path("results/result.json")

    file.write_text(json.dumps(data, indent=2))

    return file
