"""Command-line interface (testable: pass argv explicitly)."""

from __future__ import annotations

import argparse
import asyncio
import sys

from dns_benchmark.advisor import recommend
from dns_benchmark.async_engine import AsyncDNSBenchmark
from dns_benchmark.dashboard import generate_html_report
from dns_benchmark.exporter import export_csv, export_json
from dns_benchmark.qtypes import normalize_qtype
from dns_benchmark.query_generator import set_custom_domains, set_seed
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
    p.add_argument("--qtype", default="A",
                   help="query type: A or AAAA (default A)")
    p.add_argument("--domains", nargs="+", default=None,
                   help="custom query domains (default: built-in mix of global+IR domains)")
    p.add_argument("--concurrency", type=int, default=10,
                   help="max concurrent queries per server 1-100 (default 10)")
    p.add_argument("--output-dir", default="results",
                   help="directory for csv/json/html reports (default results)")
    p.add_argument("--bypass-cache", action="store_true",
                   help="use random subdomains to bust caches (mostly NXDOMAIN)")
    p.add_argument("--seed", type=int, default=None,
                   help="random seed for reproducible domain choice")
    p.add_argument("--verbose", action="store_true",
                   help="print per-query progress")
    return p


def run_cli(argv=None):
    """Run the benchmark. Returns the sorted result list (empty on fatal error)."""
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
    try:
        qtype = normalize_qtype(args.qtype)
    except ValueError as exc:
        parser.error(str(exc))

    if args.seed is not None:
        set_seed(args.seed)
    try:
        set_custom_domains(args.domains)
    except ValueError as exc:
        parser.error(str(exc))

    done = {"n": 0}
    total = args.queries * len(args.dns)

    def progress_cb(server, res):
        if not args.verbose:
            return
        done["n"] += 1
        ok, lat, err = res
        status = f"{lat:.1f}ms" if ok else (err or "FAIL")
        print(f"[{done['n']}/{total}] {server} -> {status}", flush=True)

    try:
        engine = AsyncDNSBenchmark(
            timeout=args.timeout,
            queries=args.queries,
            protocol=args.protocol,
            concurrency=args.concurrency,
            bypass_cache=args.bypass_cache,
            qtype=qtype,
            domains=args.domains,
            progress_cb=progress_cb if args.verbose else None,
        )
    except ValueError as exc:
        parser.error(str(exc))

    print(f"Benchmarking {len(args.dns)} server(s) x {args.queries} queries "
          f"via {args.protocol.upper()}/{args.qtype.upper()} ...", flush=True)
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
    finally:
        set_custom_domains(None)  # don't leak custom pool into later runs/tests

    final = []
    for item in raw:
        server, latencies = item[0], item[1]
        errors = item[2] if len(item) > 2 else {}
        stats = DNSStatistics(latencies, args.queries)
        score = DNSScore(stats).calculate()
        final.append({
            "name": server,
            "ip": server,
            "protocol": args.protocol,
            "qtype": args.qtype.upper(),
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

    print("\nRESULTS (protocol=%s qtype=%s)" % (args.protocol, args.qtype.upper()))
    for r in final:
        err_txt = "" if not r["errors"] else f" errors={r['errors']}"
        print(f"{r['ip']:>30}  score={r['score']:<6} grade={r['grade']:<2} "
              f"avg={r['average']}ms p95={r['p95']}ms loss={r['packet_loss']}%{err_txt}")

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

    if final and all(r["packet_loss"] >= 100 for r in final):
        print("\nWARNING: all servers failed (100% loss). "
              "Check connection/firewall or try --protocol doh.",
              file=sys.stderr)

    return final


def main(argv=None) -> int:
    """Exit-code wrapper: 0 ok, 1 fatal error, 2 total failure (100% loss)."""
    try:
        res = run_cli(argv)
    except SystemExit as exc:
        raise  # argparse errors keep their own exit code
    if not res:
        return 1
    if all(r.get("packet_loss", 100) >= 100 for r in res):
        return 2
    return 0
