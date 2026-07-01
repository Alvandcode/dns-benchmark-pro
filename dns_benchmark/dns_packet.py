import secrets

TYPE_A = 1


def build_query(domain, qtype=TYPE_A):

    tid = secrets.token_bytes(2)

    packet = tid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"

    for part in domain.split("."):
        packet += bytes([len(part)]) + part.encode()

    packet += b"\x00"
    packet += qtype.to_bytes(2, "big") + b"\x00\x01"

    return tid, packet


def validate_response(resp, tid):

    if len(resp) < 12:
        return False

    if resp[:2] != tid:
        return False

    flags = int.from_bytes(resp[2:4], "big")

    qr = (flags >> 15) & 1
    rcode = flags & 0xF

    return qr == 1 and rcode in (0, 3)
