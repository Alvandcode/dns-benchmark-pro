"""DNS packet builder / validator (RFC 1035).

Only RCODE 0 (NOERROR) is treated as success. NXDOMAIN (RCODE 3) is
NOT success so benchmarks measure real positive answers.
"""

import secrets

TYPE_A = 1
TYPE_AAAA = 28

_MAX_LABEL = 63
_MAX_NAME = 253


def _encode_name(domain: str) -> bytes:
    """Validate and encode a domain name to DNS wire format (without root)."""
    if not isinstance(domain, str) or not domain:
        raise ValueError("domain must be a non-empty string")

    # Allow a single trailing dot (FQDN form) but not empty labels elsewhere.
    name = domain.strip().lower()
    if name.endswith("."):
        name = name[:-1]

    if not name or len(name) > _MAX_NAME:
        raise ValueError(f"invalid domain length: {domain!r}")

    if ".." in name or name.startswith(".") or name.startswith("-"):
        raise ValueError(f"invalid domain format: {domain!r}")

    out = b""
    for part in name.split("."):
        if not part or len(part) > _MAX_LABEL:
            raise ValueError(f"invalid DNS label {part!r} in {domain!r}")
        try:
            encoded = part.encode("idna")
        except Exception as exc:
            raise ValueError(f"invalid domain label {part!r}: {exc}") from exc
        if len(encoded) == 0 or len(encoded) > _MAX_LABEL:
            raise ValueError(f"invalid DNS label {part!r} in {domain!r}")
        # LDH rule (letters-digits-hyphen, no leading/trailing hyphen)
        if encoded.startswith(b"-") or encoded.endswith(b"-"):
            raise ValueError(f"invalid DNS label {part!r} in {domain!r}")
        out += bytes([len(encoded)]) + encoded
    return out


def build_query(domain, qtype=TYPE_A):
    """Build a DNS query. Returns (transaction_id, packet)."""
    if not isinstance(qtype, int) or not 1 <= qtype <= 65535:
        raise ValueError(f"invalid qtype: {qtype!r}")

    qname = _encode_name(domain)

    tid = secrets.token_bytes(2)

    header = tid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
    question = qname + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"

    return tid, header + question


def validate_response(resp, tid, expected_qname_wire=None):
    """Validate a DNS response.

    Checks: min length, TID match, QR=1, OPCODE=0, RCODE=0 (NOERROR only),
    QDCOUNT=1. Optionally verifies the echoed QNAME when provided.
    """
    if not isinstance(resp, (bytes, bytearray)) or len(resp) < 12:
        return False

    if bytes(resp[:2]) != bytes(tid):
        return False

    flags = int.from_bytes(resp[2:4], "big")
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF

    if qr != 1 or opcode != 0 or rcode != 0:
        return False

    qdcount = int.from_bytes(resp[4:6], "big")
    if qdcount != 1:
        return False

    # TC (truncated) responses need TCP retry; don't count UDP-truncated as valid here.
    tc = (flags >> 9) & 1
    if tc:
        return False

    if expected_qname_wire is not None:
        # Question section starts at byte 12: QNAME + QTYPE(2) + QCLASS(2)
        try:
            qname_len = len(expected_qname_wire) + 1  # + root byte
            question = bytes(resp[12:12 + qname_len + 4])
            if len(question) < qname_len + 4:
                return False
            if question[:qname_len] != expected_qname_wire + b"\x00":
                return False
        except Exception:
            return False

    return True


def _skip_name(buf: bytes, off: int) -> int:
    """Skip a (possibly compressed) domain name. Returns offset after it."""
    jumped = False
    start_off = off
    guard = 0
    while True:
        if off >= len(buf) or guard > 64:
            raise ValueError("truncated name")
        guard += 1
        length = buf[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if off + 1 >= len(buf):
                raise ValueError("truncated pointer")
            off += 2
            break  # pointer always terminates the name
        off += 1 + length
        if not jumped and off > len(buf):
            raise ValueError("truncated label")
    return off


def parse_response(resp, tid):
    """Minimal response parser for hijack analysis.

    Returns dict with: ok_tid, qr, opcode, tc, rcode, qdcount, ancount,
    answers (list of A-record IP strings). Never raises on hostile input.
    """
    out = {"ok_tid": False, "qr": 0, "opcode": 0, "tc": 0, "rcode": -1,
           "qdcount": 0, "ancount": 0, "answers": []}
    try:
        if not isinstance(resp, (bytes, bytearray)) or len(resp) < 12:
            return out
        buf = bytes(resp)
        out["ok_tid"] = buf[:2] == bytes(tid)
        flags = int.from_bytes(buf[2:4], "big")
        out["qr"] = (flags >> 15) & 1
        out["opcode"] = (flags >> 11) & 0xF
        out["tc"] = (flags >> 9) & 1
        out["rcode"] = flags & 0xF
        out["qdcount"] = int.from_bytes(buf[4:6], "big")
        out["ancount"] = int.from_bytes(buf[6:8], "big")
        if out["qr"] != 1 or not out["ok_tid"]:
            return out
        off = 12
        for _ in range(min(out["qdcount"], 8)):
            off = _skip_name(buf, off)
            off += 4  # QTYPE + QCLASS
        for _ in range(min(out["ancount"], 32)):
            off = _skip_name(buf, off)
            if off + 10 > len(buf):
                break
            rtype = int.from_bytes(buf[off:off + 2], "big")
            rclass = int.from_bytes(buf[off + 2:off + 4], "big")
            rdlen = int.from_bytes(buf[off + 8:off + 10], "big")
            off += 10
            rdata = buf[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rclass == 1 and rdlen == 4 and len(rdata) == 4:
                out["answers"].append(".".join(str(b) for b in rdata))
        return out
    except Exception:
        return out
