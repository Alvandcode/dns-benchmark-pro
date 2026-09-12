"""SQLite history store for periodic monitoring.

Schema:
  runs(id, ts_utc, protocol, qtype, queries, runs, preset, domain_group)
  results(run_id, server, score, grade, average, median, p95,
          packet_loss, succeeded, hijack, errors_json)
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def connect(path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL,
            protocol TEXT DEFAULT '',
            qtype TEXT DEFAULT '',
            queries INTEGER DEFAULT 0,
            runs INTEGER DEFAULT 1,
            preset TEXT DEFAULT '',
            domain_group TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS results(
            run_id INTEGER NOT NULL REFERENCES runs(id),
            server TEXT NOT NULL,
            score REAL DEFAULT 0,
            grade TEXT DEFAULT '',
            average REAL DEFAULT 0,
            median REAL DEFAULT 0,
            p95 REAL DEFAULT 0,
            packet_loss REAL DEFAULT 0,
            succeeded INTEGER DEFAULT 0,
            hijack TEXT DEFAULT '',
            errors_json TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
        CREATE INDEX IF NOT EXISTS idx_results_server ON results(server);
        """
    )
    conn.commit()


def save_run(conn: sqlite3.Connection, meta: dict, rows: list) -> int:
    """Persist one benchmark `final` list. Returns the run id."""
    if not rows:
        raise ValueError("no rows to save (empty result list)")
    cur = conn.execute(
        "INSERT INTO runs(ts_utc, protocol, qtype, queries, runs, preset, domain_group)"
        " VALUES(?,?,?,?,?,?,?)",
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            str(meta.get("protocol", "")),
            str(meta.get("qtype", "")),
            int(meta.get("queries", 0) or 0),
            int(meta.get("runs", 1) or 1),
            str(meta.get("preset", "") or ""),
            str(meta.get("domain_group", "") or ""),
        ),
    )
    run_id = cur.lastrowid
    for r in rows:
        errors = r.get("errors", {})
        conn.execute(
            "INSERT INTO results(run_id, server, score, grade, average, median,"
            " p95, packet_loss, succeeded, hijack, errors_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                str(r.get("ip", r.get("name", ""))),
                float(r.get("score", 0) or 0),
                str(r.get("grade", "")),
                float(r.get("average", 0) or 0),
                float(r.get("median", 0) or 0),
                float(r.get("p95", 0) or 0),
                float(r.get("packet_loss", 0) or 0),
                int(r.get("succeeded", 0) or 0),
                str(r.get("hijack", "") or ""),
                json.dumps(errors if isinstance(errors, dict) else {}),
            ),
        )
    conn.commit()
    return run_id


def load_history(conn: sqlite3.Connection, limit_runs: int = 10,
                 server: str | None = None) -> list:
    """Latest runs (newest first). Each item: run meta + its result rows."""
    if limit_runs < 1:
        raise ValueError("limit must be >= 1")
    runs = conn.execute(
        "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit_runs,)
    ).fetchall()
    out = []
    for run in runs:
        q = "SELECT * FROM results WHERE run_id = ?"
        params: tuple = (run["id"],)
        if server:
            q += " AND server = ?"
            params = (run["id"], server)
        rows = conn.execute(q, params).fetchall()
        out.append({"run": dict(run), "results": [dict(r) for r in rows]})
    return out


def series(conn: sqlite3.Connection, server: str,
           limit_runs: int = 30) -> list:
    """Time-ordered (oldest first) score/avg series for one server."""
    rows = conn.execute(
        "SELECT r.ts_utc, s.score, s.average, s.p95, s.packet_loss"
        " FROM results s JOIN runs r ON r.id = s.run_id"
        " WHERE s.server = ? ORDER BY r.id ASC LIMIT ?",
        (server, limit_runs),
    ).fetchall()
    return [dict(r) for r in rows]


def servers(conn: sqlite3.Connection) -> list:
    rows = conn.execute("SELECT DISTINCT server FROM results ORDER BY server").fetchall()
    return [r["server"] for r in rows]
