import statistics


class DNSStatistics:

    def __init__(self, latencies, total):
        self.latencies = latencies
        self.total = total

    @property
    def average(self):
        return statistics.mean(self.latencies) if self.latencies else 0

    @property
    def median(self):
        return statistics.median(self.latencies) if self.latencies else 0

    @property
    def p95(self):
        if not self.latencies:
            return 0
        k = int(len(self.latencies) * 0.95) - 1
        return self.latencies[max(k, 0)]

    @property
    def packet_loss(self):
        return 100 - (len(self.latencies) / self.total * 100)
