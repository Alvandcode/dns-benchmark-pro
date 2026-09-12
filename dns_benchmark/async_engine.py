"""Concurrent DNS benchmark engine (UDP / DoH / DoT)."""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections import Counter

from dns_benchmark.dns_client import dns_query
from dns_benchmark.doh_client import doh_query
from dns_benchmark.dot_client import dot_query
from dns_benchmark.qtypes import normalize_qtype
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
                 concurrency=10, bypass_cache=False, qtype=1, domains=None,
                 progress_cb=None):
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
        self.qtype = normalize_qtype(qtype)
        if domains is not None:
            pool = [d.strip() for d in domains if isinstance(d, str) and d.strip()]
            if not pool:
                raise ValueError("--domains must be a non-empty list")
            self.domains = pool
        else:
            self.domains = None
        self.progress_cb = progress_cb
        self._pool: concurrent.futures.ThreadPoolExecutor | None = None

    def _executor(self, n_servers: int) -> concurrent.futures.ThreadPoolExecutor:
        if self._pool is None:
            # Dedicated pool: default shared pool (min(32, cpu+4)) would
            # throttle e.g. 3 servers x 10 concurrent = 30 parallel queries
            # on small machines. Size it explicitly, cap at 100 threads.
            workers = max(1, min(self.concurrency * max(1, n_servers), 100))
            self._pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="dnsbench"
            )
        return self._pool

    def close(self) -> None:
        pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)

    def _single_query(self, server: str):
        fn = _query_fn(self.protocol)
        domain = random_domain(bypass_cache=self.bypass_cache, pool=self.domains)
        try:
            return fn(server, domain, self.timeout, self.qtype)
        except Exception as exc:  # never let one query kill the run
            return False, None, f"ERROR: {type(exc).__name__}"

    async def run_single(self, server):
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(self.concurrency)
        pool = self._executor(1)

        async def one():
            async with sem:
                res = await loop.run_in_executor(pool, self._single_query, server)
                if self.progress_cb is not None:
                    try:
                        self.progress_cb(server, res)
                    except Exception:
                        pass
                return res

        results = await asyncio.gather(*(one() for _ in range(self.queries)))
        latencies = []
        errors: Counter = Counter()
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
        self._executor(len(servers))  # size pool for the full run
        try:
            tasks = [self.run_single(s) for s in servers]
            return await asyncio.gather(*tasks, return_exceptions=False)
        finally:
            self.close()
