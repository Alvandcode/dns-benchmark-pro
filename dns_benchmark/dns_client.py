"""UDP DNS client (port 53) with TCP fallback on truncation."""

from __future__ import annotations

import ipaddress
import socket
import struct
import time

from dns_benchmark.dns_packet import _encode_name, build_query, validate_response
from dns_benchmark.qtypes import normalize_qtype


def _family_for_ip(dns_ip: str):
    try:
        addr = ipaddress.ip_address((dns_ip or "").strip())
    except Exception as exc:
        raise ValueError(f"invalid DNS server IP: {dns_ip!r}") from exc
    if isinstance(addr, ipaddress.IPv4Address):
        return socket.AF_INET, str(addr)
    return socket.AF_INET6, str(addr)


def resolve_target(dns_ip: str):
    """Return (family, sockaddr) for a DNS server IP.

    Link-local IPv6 literals carry a scope id (``fe80::1%eth0``) which a
    plain 2-tuple cannot express; those fall back to getaddrinfo so the
    full 4-tuple (host, port, flowinfo, scopeid) is used.
    """
    family, clean_ip = _family_for_ip(dns_ip)
    if "%" in clean_ip:
        try:
            infos = socket.getaddrinfo(clean_ip, 53, family, socket.SOCK_DGRAM)
        except OSError as exc:
            raise ValueError(f"unresolvable scoped address {dns_ip!r}: {exc}") from exc
        if not infos:
            raise ValueError(f"unresolvable scoped address: {dns_ip!r}")
        return infos[0][0], infos[0][4]
    return family, (clean_ip, 53)


def _is_truncated(resp: bytes) -> bool:
    if len(resp) < 4:
        return False
    flags = int.from_bytes(resp[2:4], "big")
    return bool((flags >> 9) & 1)


def _query_tcp(family, sockaddr, packet, tid, qname_wire, timeout) -> tuple:
    """DNS-over-TCP fallback (length-prefixed). Returns (ok, latency|None, err)."""
    start = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            hdr = _recvall(sock, 2)
            if len(hdr) != 2:
                return False, None, "TRUNCATED"
            (resp_len,) = struct.unpack("!H", hdr)
            if not 12 <= resp_len <= 65535:
                return False, None, "INVALID_LENGTH"
            response = _recvall(sock, resp_len)
    except socket.timeout:
        return False, None, "TIMEOUT"
    except OSError as exc:
        return False, None, f"NETWORK: {exc.strerror or exc}"
    except Exception as exc:
        return False, None, f"ERROR: {type(exc).__name__}"

    latency = (time.perf_counter() - start) * 1000.0
    if len(response) != resp_len or not validate_response(
        response, tid, expected_qname_wire=qname_wire
    ):
        return False, latency, "INVALID"
    return True, latency, None


def _recvall(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def dns_query(dns_ip, domain, timeout=3.0, qtype=1):
    """Send one DNS query over UDP (TCP fallback on TC=1).

    Returns (success, latency_ms|None, error|None).
    """
    try:
        qtype_num = normalize_qtype(qtype)
    except ValueError as exc:
        return False, None, f"BAD_QUERY: {exc}"
    try:
        qname_wire = _encode_name(domain)
        tid, packet = build_query(domain, qtype_num)
    except ValueError as exc:
        return False, None, f"BAD_QUERY: {exc}"

    try:
        family, sockaddr = resolve_target(dns_ip)
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
            sock.sendto(packet, sockaddr)
            response, _ = sock.recvfrom(5120)
    except socket.timeout:
        return False, None, "TIMEOUT"
    except OSError as exc:
        return False, None, f"NETWORK: {exc.strerror or exc}"
    except Exception as exc:  # defensive: never leak internals verbatim
        return False, None, f"ERROR: {type(exc).__name__}"

    latency = (time.perf_counter() - start) * 1000.0

    # Truncated UDP -> retry over TCP (covers large/DNSSEC answers).
    if _is_truncated(response):
        ok, tcp_latency, err = _query_tcp(
            family, sockaddr, packet, tid, qname_wire, timeout
        )
        if ok:
            return True, tcp_latency, None
        return False, tcp_latency if tcp_latency is not None else latency, (
            err or "TRUNCATED"
        )

    if not validate_response(response, tid, expected_qname_wire=qname_wire):
        return False, latency, "INVALID"

    return True, latency, None
