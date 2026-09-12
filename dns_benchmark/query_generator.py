"""Query name generator.

Default mode returns REAL domains (positive NOERROR answers) so the
benchmark measures normal browsing latency. The old behaviour of
``<random>.google.com`` almost always yields NXDOMAIN, which skews
results toward the NXDOMAIN path and breaks filtering resolvers.

Use ``bypass_cache=True`` only when you explicitly want cache-busting
(random subdomains, mostly NXDOMAIN).

Thread-safe: a lock guards the shared RNG because queries run in a
thread pool.
"""

from __future__ import annotations

import random
import secrets
import threading

# Mix of global + Iranian-popular domains for a fair benchmark.
BASE = [
    "google.com",
    "cloudflare.com",
    "wikipedia.org",
    "github.com",
    "microsoft.com",
    "aparat.com",
    "digikala.com",
    "divar.ir",
    "shaparak.ir",
    "cloudflare-dns.com",
]

_rng = random.Random()
_lock = threading.Lock()
_custom_pool: list | None = None


def set_seed(seed) -> None:
    """Make domain selection reproducible."""
    with _lock:
        _rng.seed(seed)


def set_custom_domains(domains) -> None:
    """Override the query pool (validated non-empty list of strings)."""
    global _custom_pool
    if domains is None:
        _custom_pool = None
        return
    pool = [d.strip() for d in domains if isinstance(d, str) and d.strip()]
    if not pool:
        raise ValueError("--domains must be a non-empty list of domain names")
    _custom_pool = pool


def _pool() -> list:
    return _custom_pool or BASE


def random_domain(bypass_cache: bool = False, pool=None) -> str:
    if pool:
        base_list = list(pool)
    else:
        with _lock:
            base_list = list(_pool())
            base = _rng.choice(base_list)
        if not bypass_cache:
            return base
        return f"{secrets.token_hex(3)}.{base}"
    # Explicit pool path (also thread-safe via local Random choice under lock)
    with _lock:
        base = _rng.choice(base_list)
    if not bypass_cache:
        return base
    return f"{secrets.token_hex(3)}.{base}"


def domain_list(n: int, bypass_cache: bool = False, pool=None) -> list:
    return [random_domain(bypass_cache=bypass_cache, pool=pool)
            for _ in range(max(0, int(n)))]
