"""Scoring model for DNS benchmark.

Formula (documented so results are reproducible):
    if packet_loss >= 100 or no successful sample: score = 0
    else:
        score = 100
        score -= packet_loss * 0.7        # reliability dominates
        score -= min(average / 4, 20)     # avg latency penalty (80ms+ => -20)
        score -= min(max(p95 - average, 0) / 10, 10)  # tail-latency (jitter) penalty

Rationale: loss hurts most, then average speed, then stability (p95-average).
"""

from __future__ import annotations


class DNSScore:
    def __init__(self, stats):
        self.stats = stats

    def calculate(self) -> float:
        loss = float(getattr(self.stats, "packet_loss", 100.0) or 0.0)
        avg = float(getattr(self.stats, "average", 0.0) or 0.0)
        p95 = float(getattr(self.stats, "p95", avg) or 0.0)
        succeeded = int(getattr(self.stats, "succeeded", 0) or 0)

        if succeeded <= 0 or loss >= 100.0:
            return 0.0

        score = 100.0
        score -= loss * 0.7
        score -= min(avg / 4.0, 20.0)
        score -= min(max(p95 - avg, 0.0) / 10.0, 10.0)

        return float(max(0.0, round(score, 2)))


def grade(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "F"
    if s >= 95:
        return "A+"
    if s >= 90:
        return "A"
    if s >= 80:
        return "B"
    if s >= 65:
        return "C"
    if s >= 40:
        return "D"
    return "F"
