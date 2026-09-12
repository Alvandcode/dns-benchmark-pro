"""Periodic monitoring loop + trend chart.

The loop reuses the normal benchmark pass (passed in as a callable so
this module stays UI-free and unit-testable without network).
"""

from __future__ import annotations

import time

from dns_benchmark import store


def run_watch(db_path, meta: dict, tick_fn, interval: float,
              count: int = 0, sleep_fn=None) -> list:
    """Run benchmark ticks periodically, persisting each to SQLite.

    tick_fn: zero-arg callable returning one `final` result list.
    interval: seconds between ticks (> 0). count: 0 = until Ctrl+C.
    Returns the last tick's final list (possibly []).
    """
    if interval <= 0 or interval > 86400:
        raise ValueError("interval must be between 0 and 86400 seconds")
    if count < 0:
        raise ValueError("count must be >= 0")
    sleep = sleep_fn or time.sleep
    conn = store.connect(db_path)
    store.init_db(conn)
    last: list = []
    n = 0
    try:
        while count <= 0 or n < count:
            n += 1
            final = tick_fn() or []
            run_id = store.save_run(conn, meta, final) if final else None
            best = max(final, key=lambda r: float(r.get("score", -1))) if final else None
            if best is not None:
                print(f"[watch {n}] run #{run_id}: best={best.get('ip')} "
                      f"score={best.get('score')} "
                      f"n={len(final)}", flush=True)
            else:
                print(f"[watch {n}] run failed (empty result)", flush=True)
            last = final
            if count > 0 and n >= count:
                break
            sleep(interval)
    except KeyboardInterrupt:
        print(f"\nStopped after {n} tick(s). History kept in {db_path}.")
    finally:
        conn.close()
    return last


def generate_trend_chart(history_series: dict, path="results/trend.png"):
    """Line chart of score over time per server. Returns path or None.

    history_series: {server: [ {ts_utc, score, ...}, ... ]}.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None
    try:
        from pathlib import Path

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fig, ax = plt.subplots(figsize=(10, 4))
        for server, points in sorted(history_series.items()):
            if not points:
                continue
            xs = list(range(1, len(points) + 1))
            ys = [float(p.get("score", 0) or 0) for p in points]
            ax.plot(xs, ys, marker="o", label=str(server))
        ax.set_title("DNS score trend (higher is better)")
        ax.set_xlabel("run # (oldest → newest)")
        ax.set_ylabel("score")
        ax.set_ylim(0, 105)
        ax.legend(fontsize="small")
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        return path
    except Exception:
        return None
