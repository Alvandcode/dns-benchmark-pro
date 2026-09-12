"""Wave-2 tests: SQLite store, watch loop, history/trend CLI."""

import pytest

from dns_benchmark import monitor, store


def _row(ip="1.1.1.1", score=90.0):
    return {"name": ip, "ip": ip, "protocol": "udp", "qtype": "A",
            "average": 20.0, "median": 20.0, "p95": 25.0, "packet_loss": 0.0,
            "succeeded": 5, "errors": {}, "score": score, "grade": "A",
            "hijack": "clean"}


def _db(tmp_path):
    conn = store.connect(tmp_path / "h.db")
    store.init_db(conn)
    return conn


def test_store_roundtrip(tmp_path):
    conn = _db(tmp_path)
    meta = {"protocol": "udp", "qtype": "A", "queries": 5, "runs": 1,
            "preset": "ir", "domain_group": "all"}
    rid = store.save_run(conn, meta, [_row("1.1.1.1", 90.0), _row("8.8.8.8", 70.0)])
    assert rid == 1
    hist = store.load_history(conn, limit_runs=10)
    assert len(hist) == 1 and len(hist[0]["results"]) == 2
    assert hist[0]["run"]["preset"] == "ir"
    assert store.servers(conn) == ["1.1.1.1", "8.8.8.8"]
    conn.close()


def test_store_rejects_empty(tmp_path):
    conn = _db(tmp_path)
    with pytest.raises(ValueError):
        store.save_run(conn, {}, [])
    with pytest.raises(ValueError):
        store.load_history(conn, limit_runs=0)
    conn.close()


def test_series_ordering(tmp_path):
    conn = _db(tmp_path)
    meta = {"protocol": "udp", "qtype": "A", "queries": 2, "runs": 1}
    store.save_run(conn, meta, [_row("1.1.1.1", 80.0)])
    store.save_run(conn, meta, [_row("1.1.1.1", 90.0)])
    pts = store.series(conn, "1.1.1.1")
    assert [p["score"] for p in pts] == [80.0, 90.0]
    conn.close()


def test_watch_loop_saves_ticks(tmp_path):
    calls = {"n": 0}

    def tick():
        calls["n"] += 1
        return [_row("1.1.1.1", 80.0 + calls["n"])]

    meta = {"protocol": "udp", "qtype": "A", "queries": 2, "runs": 1}
    last = monitor.run_watch(str(tmp_path / "h.db"), meta, tick,
                             interval=60, count=2,
                             sleep_fn=lambda s: calls.setdefault("slept", s))
    assert calls["n"] == 2 and last[0]["score"] == 82.0
    conn = store.connect(tmp_path / "h.db")
    try:
        assert len(store.load_history(conn, 10)) == 2
    finally:
        conn.close()


def test_watch_validates():
    with pytest.raises(ValueError):
        monitor.run_watch(":memory:", {}, lambda: [], interval=0, count=1)
    with pytest.raises(ValueError):
        monitor.run_watch(":memory:", {}, lambda: [], interval=1, count=-1)


def test_watch_keyboard_interrupt(tmp_path, monkeypatch):
    def tick():
        return [_row()]

    def boom(s):
        raise KeyboardInterrupt

    meta = {"protocol": "udp", "qtype": "A", "queries": 1, "runs": 1}
    last = monitor.run_watch(str(tmp_path / "h.db"), meta, tick,
                             interval=60, count=0, sleep_fn=boom)
    assert last and last[0]["ip"] == "1.1.1.1"


def test_trend_chart(tmp_path):
    series = {"1.1.1.1": [{"ts_utc": "t", "score": 80.0},
                          {"ts_utc": "t", "score": 90.0}],
              "8.8.8.8": [{"ts_utc": "t", "score": 70.0}]}
    out = monitor.generate_trend_chart(series, tmp_path / "trend.png")
    assert out is not None and out.is_file()


def test_cli_history(tmp_path, capsys):
    from dns_benchmark.cli import run_cli

    db = tmp_path / "h.db"
    conn = store.connect(db)
    store.init_db(conn)
    store.save_run(conn, {"protocol": "udp", "qtype": "A", "queries": 2,
                          "runs": 1}, [_row("9.9.9.9", 88.0)])
    conn.close()
    with pytest.raises(SystemExit) as exc:
        run_cli(["--history", "--db", str(db)])
    assert exc.value.code == 0
    assert "9.9.9.9" in capsys.readouterr().out


def test_cli_history_missing_db(tmp_path):
    from dns_benchmark.cli import run_cli

    with pytest.raises(SystemExit) as exc:
        run_cli(["--history", "--db", str(tmp_path / "nope.db")])
    assert exc.value.code != 0


def test_cli_trend(tmp_path, capsys):
    from dns_benchmark.cli import run_cli

    db = tmp_path / "h.db"
    conn = store.connect(db)
    store.init_db(conn)
    meta = {"protocol": "udp", "qtype": "A", "queries": 2, "runs": 1}
    store.save_run(conn, meta, [_row("1.1.1.1", 80.0)])
    store.save_run(conn, meta, [_row("1.1.1.1", 90.0)])
    conn.close()
    with pytest.raises(SystemExit) as exc:
        run_cli(["--trend", "--db", str(db), "--output-dir", str(tmp_path)])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "1.1.1.1" in out and "trend.png" in out
    assert (tmp_path / "trend.png").is_file()


def test_cli_trend_unknown_server(tmp_path):
    from dns_benchmark.cli import run_cli

    db = tmp_path / "h.db"
    conn = store.connect(db)
    store.init_db(conn)
    store.save_run(conn, {}, [_row("1.1.1.1")])
    conn.close()
    with pytest.raises(SystemExit) as exc:
        run_cli(["--trend", "2.2.2.2", "--db", str(db)])
    assert exc.value.code != 0


def test_cli_watch_flags_validation():
    from dns_benchmark.cli import run_cli

    with pytest.raises(SystemExit) as exc:
        run_cli(["--watch", "-5", "--dns", "1.1.1.1"])
    assert exc.value.code != 0
    with pytest.raises(SystemExit) as exc:
        run_cli(["--watch", "5", "--watch-count", "-1", "--dns", "1.1.1.1"])
    assert exc.value.code != 0


def test_console_entry_is_main_with_exit_codes():
    """pyproject console script must be cli:main (not run_cli) so exit codes work."""
    import pathlib

    text = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'dns-benchmark = "dns_benchmark.cli:main"' in text
    from dns_benchmark.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_series_returns_latest_not_oldest(tmp_path):
    conn = store.connect(tmp_path / "h.db")
    store.init_db(conn)
    meta = {"protocol": "udp", "qtype": "A", "queries": 1, "runs": 1}
    for i in range(35):
        store.save_run(conn, meta, [_row("1.1.1.1", float(i))])
    pts = store.series(conn, "1.1.1.1", limit_runs=30)
    assert len(pts) == 30
    assert pts[0]["score"] == 5.0 and pts[-1]["score"] == 34.0
    conn.close()


def test_aggregate_median_is_mean(tmp_path=None):
    from dns_benchmark.compare import aggregate

    run1 = [{"ip": "a", "name": "a", "score": 90.0, "average": 20.0,
             "median": 10.0, "p95": 25.0, "packet_loss": 0.0, "succeeded": 5,
             "errors": {}}]
    run2 = [{"ip": "a", "name": "a", "score": 90.0, "average": 20.0,
             "median": 30.0, "p95": 25.0, "packet_loss": 0.0, "succeeded": 5,
             "errors": {}}]
    out = aggregate([run1, run2])
    assert out[0]["median"] == 20.0
