"""Latency statistics for DNS benchmark results."""

import math
import statistics


class DNSStatistics:
    """Compute latency stats from successful query latencies (ms)."""

    def __init__(self, latencies, total):
        # Filter out None / non-numeric defensively; keep insertion order copy.
        clean = []
        for v in (latencies or []):
            if isinstance(v, (int, float)) and math.isfinite(v) and v >= 0:
                clean.append(float(v))
        self.latencies = clean
        self.total = total if isinstance(total, int) and total > 0 else 0

    @property
    def succeeded(self) -> int:
        return len(self.latencies)

    @property
    def average(self) -> float:
        return float(statistics.mean(self.latencies)) if self.latencies else 0.0

    @property
    def median(self) -> float:
        return float(statistics.median(self.latencies)) if self.latencies else 0.0

    @property
    def minimum(self) -> float:
        return float(min(self.latencies)) if self.latencies else 0.0

    @property
    def maximum(self) -> float:
        return float(max(self.latencies)) if self.latencies else 0.0

    @property
    def stdev(self) -> float:
        if len(self.latencies) < 2:
            return 0.0
        try:
            return float(statistics.stdev(self.latencies))
        except statistics.StatisticsError:
            return 0.0

    @property
    def p95(self) -> float:
        """95th percentile (nearest-rank) over SORTED latencies."""
        if not self.latencies:
            return 0.0
        ordered = sorted(self.latencies)
        # nearest-rank: ceil(0.95 * n) - 1 (0-indexed)
        k = math.ceil(0.95 * len(ordered)) - 1
        k = max(0, min(k, len(ordered) - 1))
        return float(ordered[k])

    @property
    def packet_loss(self) -> float:
        if self.total <= 0:
            return 0.0
        loss = 100.0 - (len(self.latencies) / self.total * 100.0)
        return float(max(0.0, min(100.0, loss)))
