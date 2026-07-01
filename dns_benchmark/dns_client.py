import socket
import time
from dns_benchmark.dns_packet import build_query, validate_response


def dns_query(dns_ip, domain, timeout=3.0, qtype=1):

    tid, packet = build_query(domain, qtype)

    try:
        infos = socket.getaddrinfo(dns_ip, 53, 0, socket.SOCK_DGRAM)
        family, socktype, proto, _, sockaddr = infos[0]

        start = time.perf_counter()

        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, sockaddr)
            response, _ = sock.recvfrom(4096)

        latency = (time.perf_counter() - start) * 1000

        if not validate_response(response, tid):
            return False, latency, "INVALID"

        return True, latency, None

    except socket.timeout:
        return False, timeout * 1000, "TIMEOUT"

    except Exception as e:
        return False, None, str(e)
