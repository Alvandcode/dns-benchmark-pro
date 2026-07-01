import argparse
import asyncio

from dns_benchmark.async_engine import AsyncDNSBenchmark
from dns_benchmark.statistics import DNSStatistics
from dns_benchmark.scoring import DNSScore, grade
from dns_benchmark.exporter import export_csv, export_json
from dns_benchmark.dashboard import generate_html_report
from dns_benchmark.advisor import recommend


def run_cli():

    parser = argparse.ArgumentParser(description="DNS Benchmark Pro")

    parser.add_argument("--queries", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=3)

    args = parser.parse_args()

    dns_list = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    engine = AsyncDNSBenchmark(timeout=args.timeout, queries=args.queries)

    results = asyncio.run(engine.run_all(dns_list))

    final = []

    for ip, latencies in results:

        stats = DNSStatistics(latencies, args.queries)

        score = DNSScore(stats).calculate()

        final.append({
            "name": ip,
            "ip": ip,
            "average": stats.average,
            "median": stats.median,
            "p95": stats.p95,
            "packet_loss": stats.packet_loss,
            "score": score,
            "grade": grade(score)
        })

    final.sort(key=lambda x: x["score"], reverse=True)

    print("\nRESULTS")
    for r in final:
        print(r["ip"], r["score"], r["grade"])

    print("\nBEST:")
    print(recommend(final))

    print("\nFILES:")
    print(export_csv(final))
    print(export_json(final))
    print(generate_html_report(final))
