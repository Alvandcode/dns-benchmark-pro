"""Shared qtype normalisation (A/AAAA <-> 1/28)."""

from __future__ import annotations

_QTYPE_MAP = {
    "a": 1, 1: 1,
    "aaaa": 28, 28: 28,
}


def normalize_qtype(qtype) -> int:
    """Accept 1/28/'A'/'AAAA' (any case). Returns numeric code or raises."""
    if isinstance(qtype, str):
        key = qtype.strip().lower()
        if key in _QTYPE_MAP:
            return _QTYPE_MAP[key]
        raise ValueError(f"--qtype must be A or AAAA (got {qtype!r})")
    if qtype in (1, 28):
        return int(qtype)
    raise ValueError(f"--qtype must be A or AAAA (got {qtype!r})")


def qtype_to_doh(qtype) -> str:
    return "AAAA" if normalize_qtype(qtype) == 28 else "A"
