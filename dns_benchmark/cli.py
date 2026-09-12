"""Command-line interface (testable: pass argv explicitly)."""

from __future__ import annotations

import argparse
import asyncio
import sys

from dns_benchmark.advisor import recommend
from dns_benchmark.async_engine import AsyncDNSBenchmark
from dns_benchmark.dashboard import generate_html_report
from dns_benchmark.exporter import export_csv, export_json
from dns_benchmark.query_generator import set_seed
from dns_benchmark.scoring import DNSScore, grade
from dns_benchmark.statistics import DNSStatistics

DEFAULT_DNS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DNS Benchmark Pro (UDP / DoH / DoT)")
    p.add_argument("--dns", nargs="+", default=DEFAULT_DNS,
                   help="DNS servers to benchmark (IPs or DoH URLs when --protocol doh)")
    p.add_argument("--queries", type=int, default=10,
                   help="queries per server (>=1, default 10)")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-query timeout in seconds 0.1-30 (default 3)")
    p.add_argument("--protocol", choices=["udp", "doh", "dot"], default="udp",
                   help="protocol to benchmark (default udp)")
    p.add_argument("--concurrency", type=int, default=10,
                   help="max concurrent queries per server 1-100 (default 10)")
    p.add_argument("--output-dir", default="results",
                   help="directory for csv/json/html reports (default results)")
    p.add_argument("--bypass-cache", action="store_true",
                   help="use random subdomains to bust caches (mostly NXDOMAIN)")
    p.add_argument("--seed", type=int, default=None,
                   help="random seed for reproducible domain choice")
    return p


def run_cli(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.queries < 1:
        parser.error("--queries must be >= 1")
    if not 0.1 <= args.timeout <= 30:
        parser.error("--timeout must be between 0.1 and 30")
    if not args.dns:
        parser.error("--dns list is empty")
    if not 1 <= args.concurrency <= 100:
        parser.error("--concurrency must be between 1 and 100")

    if args.seed is not None:
        set_seed(args.seed)

    try:
        engine = AsyncDNSBenchmark(
            timeout=args.timeout,
            queries=args.queries,
            protocol=args.protocol,
            concurrency=args.concurrency,
            bypass_cache=args.bypass_cache,
        )
    except ValueError as exc:
        parser.error(str(exc))

    try:
        raw = asyncio.run(engine.run_all(args.dns))
    except RuntimeError as exc:
        # e.g. running inside Jupyter with a live loop
        print(f"ERROR: asyncio: {exc}\nHint: use await engine.run_all(...) in notebooks.",
              file=sys.stderr)
        return []
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return []

    final = []
    for item in raw:
        # New engine returns (server, latencies, errors); tolerate old 2-tuples.
        server, latencies = item[0], item[1]
        errors = item[2] if len(item) > 2 else {}
        stats = DNSStatistics(latencies, args.queries)
        score = DNSScore(stats).calculate()
        final.append({
            "name": server,
            "ip": server,
            "protocol": args.protocol,
            "average": round(stats.average, 2),
            "median": round(stats.median, 2),
            "p95": round(stats.p95, 2),
            "packet_loss": round(stats.packet_loss, 2),
            "succeeded": stats.succeeded,
            "errors": errors,
            "score": score,
            "grade": grade(score),
        })

    final.sort(key=lambda x: x["score"], reverse=True)

    print("\nRESULTS (protocol=%s)" % args.protocol)
    for r in final:
        print(f"{r['ip']:>22}  score={r['score']:<6} grade={r['grade']:<2} "
              f"avg={r['average']}ms p95={r['p95']}ms loss={r['packet_loss']}%")

    print("\nBEST:")
    try:
        best = recommend(final)
        print(best)
        if "warning" in best:
            print("WARNING:", best["warning"])
    except ValueError as exc:
        print(f"ERROR: {exc}")

    from pathlib import Path
    out = Path(args.output_dir)
    print("\nFILES:")
    try:
        print(export_csv(final, out / "result.csv"))
        print(export_json(final, out / "result.json"))
        print(generate_html_report(final, out / "report.html"))
    except ValueError as exc:
        print(f"ERROR: {exc}")

    return final
