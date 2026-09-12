"""DNS-over-HTTPS client (RFC 8484 JSON profile).

Uses the ``requests`` dependency (previously dead) so the README claim
of DoH support is actually true.
"""

from __future__ import annotations

import time

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

# Well-known DoH endpoints keyed by the classic IP list + generic fallback.
DOH_ENDPOINTS = {
    "1.1.1.1": "https://cloudflare-dns.com/dns-query",
    "1.0.0.1": "https://cloudflare-dns.com/dns-query",
    "8.8.8.8": "https://dns.google/resolve",
    "8.8.4.4": "https://dns.google/resolve",
    "9.9.9.9": "https://dns.quad9.net:5053/dns-query",
}


def resolve_doh_endpoint(server: str) -> str:
    server = (server or "").strip()
    if server.startswith("http://") or server.startswith("https://"):
        return server
    if server in DOH_ENDPOINTS:
        return DOH_ENDPOINTS[server]
    # Generic fallback: https://<ip>/dns-query (works for many providers
    # with valid certs; IP-literal certs may fail -> caller sees error).
    return f"https://{server}/dns-query"


def doh_query(server, domain, timeout=5.0, qtype="A"):
    """Query via DoH JSON API. Returns (success, latency_ms|None, error|None)."""
    if requests is None:
        return False, None, "MISSING_DEP: requests is not installed"
    if not domain or not isinstance(domain, str):
        return False, None, "BAD_QUERY: empty domain"
    try:
        timeout = float(timeout)
        if not 0.5 <= timeout <= 30:
            raise ValueError("timeout must be between 0.5 and 30 seconds")
    except (TypeError, ValueError) as exc:
        return False, None, f"BAD_TIMEOUT: {exc}"

    url = resolve_doh_endpoint(server)
    start = time.perf_counter()
    try:
        # Cloudflare supports RFC8484 GET; Google/Quad9 support JSON API.
        # Use JSON API which works across all three without wire-format code.
        resp = requests.get(
            url,
            params={"name": domain, "type": qtype},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        latency = (time.perf_counter() - start) * 1000.0
        if resp.status_code != 200:
            return False, latency, f"HTTP_{resp.status_code}"
        data = resp.json()
        status = data.get("Status", -1)
        if status != 0:  # 0 = NOERROR (3 = NXDOMAIN counts as failure here)
            return False, latency, f"RCODE_{status}"
        return True, latency, None
    except Exception as exc:
        err = getattr(exc, "__class__", type(exc)).__name__
        if "Timeout" in err or "timeout" in str(exc).lower():
            return False, None, "TIMEOUT"
        return False, None, f"DOH_{err}"
