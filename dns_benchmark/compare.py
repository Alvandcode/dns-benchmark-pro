"""Multi-run comparison: mean ± 95% CI across repeated benchmark runs.

Single runs are noisy (routing, cache state, rate limits). Repeating the
run N times and ranking by mean score with a confidence interval is the
honest way to pick a winner.
"""

from __future__ import annotations

import math
import statistics

from dns_benchmark.scoring import grade


def mean_ci(values: list) -> tuple:
    """Returns (mean, stdev, ci95_half_width), all rounded to 2 decimals.

    Non-finite inputs (inf/nan) are ignored so hostile or corrupt data
    can never crash aggregation.
    """
    vals = [float(v) for v in values
            if isinstance(v, (int, float)) and math.isfinite(float(v))]
    if not vals:
        return 0.0, 0.0, 0.0
    mean = statistics.mean(vals)
    if len(vals) < 2:
        return round(mean, 2), 0.0, 0.0
    stdev = statistics.stdev(vals)
    ci = 1.96 * stdev / math.sqrt(len(vals))
    return round(mean, 2), round(stdev, 2), round(ci, 2)


def aggregate(all_runs: list) -> list:
    """Aggregate per-run result lists into ranked comparison rows.

    all_runs: list of `final` lists as produced by one benchmark run.
    Returns rows sorted by score_mean desc. Each row keeps the standard
    keys (average/p95/packet_loss/score/grade...) so exporters and the
    dashboard keep working, plus runs/score_ci/avg_ci/hijack info.
    """
    if not all_runs or not all_runs[0]:
        raise ValueError("no runs to aggregate (empty)")

    by_ip: dict = {}
    order: dict = {}
    for run in all_runs:
        for row in run:
            ip = row.get("ip", row.get("name"))
            by_ip.setdefault(ip, []).append(row)
            order.setdefault(ip, row)

    out = []
    for ip, rows in by_ip.items():
        score_mean, _, score_ci = mean_ci([r.get("score", 0) for r in rows])
        avg_mean, _, avg_ci = mean_ci([r.get("average", 0) for r in rows])
        p95_mean, _, _ = mean_ci([r.get("p95", 0) for r in rows])
        med_mean, _, _ = mean_ci([r.get("median", 0) for r in rows])
        loss_mean, _, _ = mean_ci([r.get("packet_loss", 0) for r in rows])
        hijacks = {r.get("hijack", "") for r in rows if r.get("hijack")}
        first = order[ip]
        out.append({
            "name": ip,
            "ip": ip,
            "protocol": first.get("protocol", ""),
            "qtype": first.get("qtype", ""),
            "runs": len(rows),
            "average": avg_mean,
            "avg_ci": avg_ci,
            "median": med_mean,
            "p95": p95_mean,
            "packet_loss": loss_mean,
            "succeeded": sum(int(r.get("succeeded", 0) or 0) for r in rows),
            "errors": {},
            "score": score_mean,
            "score_ci": score_ci,
            "grade": grade(score_mean),
            "hijack": next(iter(hijacks), ""),
        })

    out.sort(key=lambda r: r["score"], reverse=True)
    return out
