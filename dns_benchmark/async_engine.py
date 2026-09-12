"""Concurrent DNS benchmark engine (UDP / DoH / DoT)."""

from __future__ import annotations

import asyncio
from collections import Counter

from dns_benchmark.dns_client import dns_query
from dns_benchmark.doh_client import doh_query
from dns_benchmark.dot_client import dot_query
from dns_benchmark.query_generator import random_domain


def _query_fn(protocol: str):
    protocol = (protocol or "udp").lower()
    if protocol == "doh":
        return doh_query
    if protocol == "dot":
        return dot_query
    return dns_query


class AsyncDNSBenchmark:
    def __init__(self, timeout=3, queries=10, protocol="udp",
                 concurrency=10, bypass_cache=False, qtype=1):
        if not isinstance(queries, int) or queries < 1:
            raise ValueError("--queries must be an integer >= 1")
        if not 0.1 <= float(timeout) <= 30:
            raise ValueError("--timeout must be between 0.1 and 30 seconds")
        protocol = (protocol or "udp").lower()
        if protocol not in ("udp", "doh", "dot"):
            raise ValueError("--protocol must be one of: udp, doh, dot")
        self.timeout = float(timeout)
        self.queries = int(queries)
        self.protocol = protocol
        self.concurrency = max(1, min(int(concurrency or 10), 100))
        self.bypass_cache = bool(bypass_cache)
        self.qtype = qtype

    def _single_query(self, server: str):
        fn = _query_fn(self.protocol)
        domain = random_domain(bypass_cache=self.bypass_cache)
        try:
            if self.protocol == "udp":
                return fn(server, domain, self.timeout, self.qtype)
            return fn(server, domain, self.timeout)
        except Exception as exc:  # never let one query kill the run
            return False, None, f"ERROR: {type(exc).__name__}"

    async def run_single(self, server):
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(self.concurrency)

        async def one():
            async with sem:
                return await loop.run_in_executor(None, self._single_query, server)

        results = await asyncio.gather(*(one() for _ in range(self.queries)))
        latencies = []
        errors = Counter()
        for success, latency, err in results:
            if success and isinstance(latency, (int, float)):
                latencies.append(float(latency))
            else:
                errors[err or "FAILED"] += 1
        return server, latencies, dict(errors)

    async def run_all(self, servers):
        servers = list(servers or [])
        if not servers:
            raise ValueError("server list is empty")
        # Backwards compatible: returns list of (server, latencies, errors).
        # Old callers unpacking (ip, latencies) still work if they take [:2].
        tasks = [self.run_single(s) for s in servers]
        return await asyncio.gather(*tasks, return_exceptions=False)
