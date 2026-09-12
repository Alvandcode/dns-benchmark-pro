"""Best-DNS advisor with empty-input and all-failed guards."""

from __future__ import annotations


def recommend(results):
    if not results:
        raise ValueError("no results to recommend from (empty list)")

    best = max(results, key=lambda x: float(x.get("score", -1)))

    loss = float(best.get("packet_loss", 100.0) or 0.0)
    score = float(best.get("score", 0.0) or 0.0)

    out = {
        "recommended": best.get("ip", best.get("name")),
        "score": score,
        "grade": best.get("grade"),
        "average_ms": best.get("average"),
        "p95_ms": best.get("p95"),
        "packet_loss_pct": loss,
    }

    if score < 40.0 or loss > 50.0:
        out["warning"] = (
            "No suitable DNS found: best server has "
            f"score={score} loss={loss}%. Check your connection/firewall."
        )
    return out
