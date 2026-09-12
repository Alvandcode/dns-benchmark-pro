"""Command-line interface (testable: pass argv explicitly)."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time

from dns_benchmark.advisor import recommend
from dns_benchmark.async_engine import AsyncDNSBenchmark
from dns_benchmark.compare import aggregate, mean_ci
from dns_benchmark.dashboard import generate_html_report
from dns_benchmark.exporter import export_csv, export_json
from dns_benchmark.hijack import check_server, summarize as hijack_summary
from dns_benchmark import monitor, store
from dns_benchmark.presets import list_presets, load_preset
from dns_benchmark.qtypes import normalize_qtype
from dns_benchmark.query_generator import set_custom_domains, set_seed
from dns_benchmark.scoring import DNSScore, grade
from dns_benchmark.statistics import DNSStatistics

DEFAULT_DNS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DNS Benchmark Pro (UDP / DoH / DoT)")
    p.add_argument("--dns", nargs="+", default=None,
                   help="DNS servers to benchmark (IPs or DoH URLs when --protocol doh)")
    p.add_argument("--preset", default=None,
                   help="named preset (e.g. ir: Iranian + public resolvers)")
    p.add_argument("--list-presets", action="store_true",
                   help="list available presets and exit")
    p.add_argument("--domain-group", choices=["all", "internal", "external"],
                   default="all",
                   help="with --preset: which query domains to use (default all)")
    p.add_argument("--queries", type=int, default=10,
                   help="queries per server per run (>=1, default 10)")
    p.add_argument("--runs", type=int, default=1,
                   help="repeat the whole benchmark N times and compare (default 1)")
    p.add_argument("--run-delay", type=float, default=2.0,
                   help="seconds between runs (default 2)")
    p.add_argument("--watch", type=float, default=0.0,
                   help="monitoring mode: repeat benchmark every N seconds (0=off)")
    p.add_argument("--watch-count", type=int, default=0,
                   help="ticks in watch mode, 0=infinite until Ctrl+C (default 0)")
    p.add_argument("--db", default="results/history.db",
                   help="SQLite history db for watch/history/trend")
    p.add_argument("--history", nargs="?", const=10, type=int, default=None,
                   help="show last N runs from history db and exit (default 10)")
    p.add_argument("--trend", nargs="?", const="*", default=None,
                   help="show score trend (optionally one server) + trend.png, then exit")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-query timeout in seconds 0.1-30 (default 3)")
    p.add_argument("--protocol", choices=["udp", "doh", "dot"], default="udp",
                   help="protocol to benchmark (default udp)")
    p.add_argument("--qtype", default="A",
                   help="query type: A or AAAA (default A)")
    p.add_argument("--domains", nargs="+", default=None,
                   help="custom query domains (overrides preset pool)")
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
    p.add_argument("--hijack-check", dest="hijack_check", action="store_true",
                   default=True,
                   help="probe UDP interception via .invalid (default on for udp)")
    p.add_argument("--no-hijack-check", dest="hijack_check", action="store_false",
                   help="skip the hijack probe")
    return p


def _one_run(args, qtype, run_idx: int):
    if args.seed is not None:
        set_seed(args.seed + run_idx)  # reproducible yet varied across runs
    done = {"n": 0}
    total = args.queries * len(args.dns)

    def progress_cb(server, res):
        if not args.verbose:
            return
        done["n"] += 1
        ok, lat, err = res
        status = f"{lat:.1f}ms" if ok else (err or "FAIL")
        print(f"[run{run_idx + 1} {done['n']}/{total}] {server} -> {status}",
              flush=True)

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
    raw = asyncio.run(engine.run_all(args.dns))

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
    return final


def _show_history(args, parser) -> None:
    """Print last N runs from the SQLite db. Always exits (never benchmarks)."""
    if args.history < 1:
        parser.error("--history must be >= 1")
    from pathlib import Path

    dbp = Path(args.db)
    if not dbp.is_file():
        print(f"ERROR: no history db at {dbp} (run with --watch first)",
              file=sys.stderr)
        raise SystemExit(1)
    conn = store.connect(args.db)
    try:
        store.init_db(conn)
        hist = store.load_history(conn, limit_runs=args.history)
    finally:
        conn.close()
    if not hist:
        print("History is empty.")
        raise SystemExit(0)
    for h in hist:
        m = h["run"]
        print(f"run #{m['id']} {m['ts_utc']} {m['protocol']}/{m['qtype']} "
              f"preset={m['preset'] or '-'}")
        for r in h["results"]:
            print(f"   {r['server']:>22} score={r['score']} grade={r['grade']} "
                  f"avg={r['average']}ms loss={r['packet_loss']}% "
                  f"hijack={r['hijack'] or '-'}")
    raise SystemExit(0)


def _show_trend(args, parser) -> None:
    """Print per-server score trend + save trend.png. Always exits."""
    from pathlib import Path

    dbp = Path(args.db)
    if not dbp.is_file():
        print(f"ERROR: no history db at {dbp} (run with --watch first)",
              file=sys.stderr)
        raise SystemExit(1)
    conn = store.connect(args.db)
    try:
        store.init_db(conn)
        names = store.servers(conn)
        if args.trend != "*":
            if args.trend not in names:
                print(f"ERROR: server {args.trend!r} not in history "
                      f"(known: {', '.join(names) or 'none'})", file=sys.stderr)
                raise SystemExit(1)
            names = [args.trend]
        series = {s: store.series(conn, s, limit_runs=30) for s in names}
    finally:
        conn.close()
    if not series or all(not v for v in series.values()):
        print("History is empty.")
        raise SystemExit(0)
    for server, points in sorted(series.items()):
        scores = [float(p["score"]) for p in points]
        mean, _, ci = mean_ci(scores)
        print(f"{server:>22}  n={len(points):<3} last={scores[-1]:<6} "
              f"mean={mean}±{ci} min={min(scores)} max={max(scores)}")
    out = Path(args.output_dir) / "trend.png"
    chart = monitor.generate_trend_chart(series, out)
    print(chart if chart is not None else "Trend chart unavailable (matplotlib missing).")
    raise SystemExit(0)


def _benchmark_pass(args, qtype):
    """One full pass: N runs (+aggregate) + hijack probe. Returns (final, all_runs)."""
    all_runs = []
    for i in range(args.runs):
        if i > 0 and args.run_delay > 0:
            time.sleep(args.run_delay)
        all_runs.append(_one_run(args, qtype, i))

    if args.runs > 1:
        final = aggregate(all_runs)
    else:
        final = all_runs[0]

    # Hijack probe (UDP only; one cheap query per server).
    hijack_results = []
    if args.hijack_check and args.protocol == "udp":
        print("Hijack check (.invalid probe) ...", flush=True)
        for r in final:
            res = check_server(r["ip"], timeout=min(args.timeout, 5.0))
            hijack_results.append(res)
            r["hijack"] = res["verdict"]
            if res["verdict"] == "hijacked":
                r["hijack"] = f"HIJACKED ({', '.join(res['invalid_answers'])})"
        print(hijack_summary(hijack_results))
    elif args.hijack_check:
        for r in final:
            r["hijack"] = "n/a (non-udp)"
    else:
        for r in final:
            r["hijack"] = ""
    return final, all_runs


def run_cli(argv=None):
    """Run the benchmark. Returns the sorted result list (empty on fatal error)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_presets:
        names = list_presets()
        print("Available presets:" if names else "No presets found.")
        for n in names:
            print(f"  - {n}")
        raise SystemExit(0)

    if args.history is not None:
        _show_history(args, parser)
    if args.trend is not None:
        _show_trend(args, parser)

    preset = None
    if args.preset:
        try:
            preset = load_preset(args.preset)
        except ValueError as exc:
            parser.error(str(exc))
        if args.dns is None:
            args.dns = list(preset["dns"])
            labels = preset.get("dns_labels", {})
            if labels:
                print("Preset servers:",
                      ", ".join(f"{labels.get(s, s)} ({s})" for s in args.dns))
        if args.domains is None:
            if args.domain_group == "internal":
                args.domains = list(preset["internal_domains"])
            elif args.domain_group == "external":
                args.domains = list(preset["external_domains"])
            else:
                args.domains = list(preset["domains"])
            print(f"Preset domains [{args.domain_group}]: {len(args.domains)} names")
    if args.dns is None:
        args.dns = list(DEFAULT_DNS)

    if args.queries < 1:
        parser.error("--queries must be >= 1")
    if args.runs < 1:
        parser.error("--runs must be >= 1")
    if not 0 <= args.run_delay <= 300:
        parser.error("--run-delay must be between 0 and 300")
    if not 0 <= args.watch <= 86400:
        parser.error("--watch must be between 0 (off) and 86400")
    if args.watch_count < 0:
        parser.error("--watch-count must be >= 0")
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
    try:
        set_custom_domains(args.domains)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"Benchmarking {len(args.dns)} server(s) x {args.queries} queries "
          f"x {args.runs} run(s) via {args.protocol.upper()}/{args.qtype.upper()} ...",
          flush=True)
    try:
        if args.watch and args.watch > 0:
            meta = {
                "protocol": args.protocol,
                "qtype": args.qtype.upper(),
                "queries": args.queries,
                "runs": args.runs,
                "preset": args.preset or "",
                "domain_group": args.domain_group,
            }

            def tick():
                try:
                    passed, _ = _benchmark_pass(args, qtype)
                    return passed
                except (RuntimeError, ValueError) as exc:
                    print(f"ERROR in watch tick: {exc}", file=sys.stderr)
                    return []

            final = monitor.run_watch(args.db, meta, tick,
                                      interval=args.watch,
                                      count=args.watch_count)
            all_runs = [final] if final else []
        else:
            final, all_runs = _benchmark_pass(args, qtype)
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

    if not final:
        print("ERROR: no results (all ticks failed)", file=sys.stderr)
        return []

    if args.runs > 1:
        print(f"\nCOMPARISON ({args.runs} runs, 95% CI)")
        for i, r in enumerate(final, 1):
            print(f"{i}. {r['ip']:>22}  score={r['score']}±{r.get('score_ci', 0):<5} "
                  f"grade={r['grade']:<2} avg={r['average']}±{r.get('avg_ci', 0)}ms "
                  f"loss={r['packet_loss']}% hijack={r.get('hijack', '')}")
    else:
        print("\nRESULTS (protocol=%s qtype=%s)" % (args.protocol, args.qtype.upper()))
        for r in final:
            err_txt = "" if not r["errors"] else f" errors={r['errors']}"
            print(f"{r['ip']:>30}  score={r['score']:<6} grade={r['grade']:<2} "
                  f"avg={r['average']}ms p95={r['p95']}ms loss={r['packet_loss']}% "
                  f"hijack={r.get('hijack', '')}{err_txt}")

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
        if args.runs > 1 and not (args.watch and args.watch > 0):
            print(export_json(
                [{"run": i + 1, "results": run} for i, run in enumerate(all_runs)],
                out / "compare_runs.json"))
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
