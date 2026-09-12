"""Query name generator.

Default mode returns REAL domains (positive NOERROR answers) so the
benchmark measures normal browsing latency. The old behaviour of
``<random>.google.com`` almost always yields NXDOMAIN, which skews
results toward the NXDOMAIN path and breaks filtering resolvers.

Use ``bypass_cache=True`` only when you explicitly want cache-busting
(random subdomains, mostly NXDOMAIN).
"""

from __future__ import annotations

import random
import secrets

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


def set_seed(seed) -> None:
    """Make domain selection reproducible."""
    _rng.seed(seed)


def random_domain(bypass_cache: bool = False) -> str:
    base = _rng.choice(BASE)
    if not bypass_cache:
        return base
    # Cache-busting: random label -> usually NXDOMAIN (documented).
    return f"{secrets.token_hex(3)}.{base}"


def domain_list(n: int, bypass_cache: bool = False) -> list:
    return [random_domain(bypass_cache=bypass_cache) for _ in range(max(0, int(n)))]
