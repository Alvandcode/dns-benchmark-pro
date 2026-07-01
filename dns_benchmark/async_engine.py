import asyncio
from dns_benchmark.dns_client import dns_query
from dns_benchmark.query_generator import random_domain


class AsyncDNSBenchmark:

    def __init__(self, timeout=3, queries=10):
        self.timeout = timeout
        self.queries = queries

    async def run_single(self, ip):

        latencies = []

        for _ in range(self.queries):

            domain = random_domain()

            loop = asyncio.get_event_loop()

            success, latency, _ = await loop.run_in_executor(
                None,
                dns_query,
                ip,
                domain,
                self.timeout
            )

            if success:
                latencies.append(latency)

        return ip, latencies

    async def run_all(self, dns_list):

        tasks = [self.run_single(ip) for ip in dns_list]

        return await asyncio.gather(*tasks)
