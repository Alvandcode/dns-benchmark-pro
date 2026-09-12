"""Transparent-DNS-proxy (hijack) detection.

Decisive test uses RFC 2606 ``.invalid``: that TLD is guaranteed
non-existent, so a standards-compliant resolver MUST answer NXDOMAIN
(RCODE 3). If a server answers NOERROR with A records for
``<random>.example.invalid``, the path is intercepted (transparent proxy
or DNS hijack) and UDP latency numbers from that network cannot be
trusted at face value.

An informational ``example.com`` lookup is also recorded so users can
compare answers across servers.
"""

from __future__ import annotations

import secrets
from socket import SOCK_DGRAM
from socket import socket as _UDPSocket

from dns_benchmark.dns_client import resolve_target
from dns_benchmark.dns_packet import build_query, parse_response


def _raw_udp_query(server_ip: str, domain: str, timeout: float):
    """One raw UDP exchange. Returns (parsed_dict|None, error|None)."""
    try:
        family, sockaddr = resolve_target(server_ip)
    except ValueError:
        return None, f"invalid DNS server IP: {server_ip!r}"
    try:
        tid, packet = build_query(domain, 1)
    except ValueError as exc:
        return None, f"BAD_QUERY: {exc}"
    try:
        sock = _UDPSocket(family, SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, sockaddr)
            resp, _ = sock.recvfrom(5120)
        finally:
            sock.close()
    except Exception as exc:
        name = type(exc).__name__
        if "imeout" in name or "timed out" in str(exc).lower():
            return None, "TIMEOUT"
        return None, f"NETWORK: {name}"
    return parse_response(resp, tid), None


def check_server(server_ip: str, timeout: float = 3.0) -> dict:
    """Probe one server. Never raises; verdict is data, not exception."""
    probe = f"nx-{secrets.token_hex(4)}.example.invalid"
    parsed, err = _raw_udp_query(server_ip, probe, timeout)
    if err is not None or parsed is None:
        return {
            "server": server_ip,
            "verdict": "inconclusive",
            "detail": f"probe failed ({err}); cannot judge interception",
            "invalid_rcode": None,
            "invalid_answers": [],
            "example_answers": [],
        }
    if not parsed["ok_tid"] or parsed["qr"] != 1:
        return {
            "server": server_ip,
            "verdict": "inconclusive",
            "detail": "no valid DNS reply to probe (spoofed/foreign packet?)",
            "invalid_rcode": parsed["rcode"],
            "invalid_answers": parsed["answers"],
            "example_answers": [],
        }

    # Informational: what does this server claim for example.com?
    ex_parsed, _ = _raw_udp_query(server_ip, "example.com", timeout)
    ex_answers = ex_parsed["answers"] if ex_parsed and ex_parsed["rcode"] == 0 else []

    if parsed["rcode"] == 0 and parsed["answers"]:
        return {
            "server": server_ip,
            "verdict": "hijacked",
            "detail": (
                f".invalid answered NOERROR with {parsed['answers']} — "
                "transparent proxy/DNS hijack on UDP/53; treat UDP latencies "
                "as 'proxy latency', compare with --protocol doh"
            ),
            "invalid_rcode": 0,
            "invalid_answers": parsed["answers"],
            "example_answers": ex_answers,
        }
    if parsed["rcode"] == 3:
        return {
            "server": server_ip,
            "verdict": "clean",
            "detail": ".invalid correctly NXDOMAIN; no UDP interception seen",
            "invalid_rcode": 3,
            "invalid_answers": [],
            "example_answers": ex_answers,
        }
    return {
        "server": server_ip,
        "verdict": "inconclusive",
        "detail": f"unexpected RCODE={parsed['rcode']} for .invalid",
        "invalid_rcode": parsed["rcode"],
        "invalid_answers": parsed["answers"],
        "example_answers": ex_answers,
    }


def summarize(results: list) -> str:
    flags = [r for r in results if r.get("verdict") == "hijacked"]
    if flags:
        names = ", ".join(r["server"] for r in flags)
        return f"HIJACK SUSPECTED on: {names} — verify with --protocol doh"
    if all(r.get("verdict") == "clean" for r in results):
        return "no UDP interception detected on tested servers"
    return "hijack check inconclusive for some servers (see hijack column)"
