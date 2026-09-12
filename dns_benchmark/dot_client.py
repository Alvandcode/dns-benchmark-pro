"""DNS-over-TLS client (RFC 7858, port 853)."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import struct
import time

from dns_benchmark.dns_packet import _encode_name, build_query, validate_response
from dns_benchmark.qtypes import normalize_qtype


def dot_query(dns_ip, domain, timeout=5.0, qtype=1):
    """Query via DoT. Returns (success, latency_ms|None, error|None)."""
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
        clean_ip = str(ipaddress.ip_address((dns_ip or "").strip()))
    except Exception:
        return False, None, f"invalid DNS server IP: {dns_ip!r}"

    try:
        timeout = float(timeout)
        if not 0.5 <= timeout <= 30:
            raise ValueError("timeout must be between 0.5 and 30 seconds")
    except (TypeError, ValueError) as exc:
        return False, None, f"BAD_TIMEOUT: {exc}"

    ctx = ssl.create_default_context()
    start = time.perf_counter()
    try:
        with socket.create_connection((clean_ip, 853), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=clean_ip) as sock:
                sock.settimeout(timeout)
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
    except ssl.SSLCertVerificationError:
        return False, None, "TLS_CERT"
    except OSError as exc:
        return False, None, f"NETWORK: {getattr(exc, 'strerror', None) or exc}"
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
