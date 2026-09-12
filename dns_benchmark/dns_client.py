"""UDP DNS client (port 53)."""

from __future__ import annotations

import ipaddress
import socket
import time

from dns_benchmark.dns_packet import _encode_name, build_query, validate_response


def _family_for_ip(dns_ip: str):
    try:
        addr = ipaddress.ip_address(dns_ip.strip())
    except Exception as exc:
        raise ValueError(f"invalid DNS server IP: {dns_ip!r}") from exc
    if isinstance(addr, ipaddress.IPv4Address):
        return socket.AF_INET, str(addr)
    return socket.AF_INET6, str(addr)


def dns_query(dns_ip, domain, timeout=3.0, qtype=1):
    """Send one UDP DNS query. Returns (success, latency_ms|None, error|None)."""
    try:
        qname_wire = _encode_name(domain)
        tid, packet = build_query(domain, qtype)
    except ValueError as exc:
        return False, None, f"BAD_QUERY: {exc}"

    try:
        family, clean_ip = _family_for_ip(dns_ip)
    except ValueError as exc:
        return False, None, str(exc)

    try:
        timeout = float(timeout)
        if not 0.1 <= timeout <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds")
    except (TypeError, ValueError) as exc:
        return False, None, f"BAD_TIMEOUT: {exc}"

    start = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (clean_ip, 53))
            response, _ = sock.recvfrom(5120)
    except socket.timeout:
        return False, None, "TIMEOUT"
    except OSError as exc:
        return False, None, f"NETWORK: {exc.strerror or exc}"
    except Exception as exc:  # defensive: never leak internals verbatim
        return False, None, f"ERROR: {type(exc).__name__}"

    latency = (time.perf_counter() - start) * 1000.0

    if not validate_response(response, tid, expected_qname_wire=qname_wire):
        return False, latency, "INVALID"

    return True, latency, None
