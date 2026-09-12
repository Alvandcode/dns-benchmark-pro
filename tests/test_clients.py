import socket

from dns_benchmark.dns_client import dns_query
from dns_benchmark.doh_client import resolve_doh_endpoint
from dns_benchmark.dot_client import dot_query
from dns_benchmark.qtypes import normalize_qtype, qtype_to_doh


def test_qtype_normalisation():
    assert normalize_qtype(1) == 1
    assert normalize_qtype("a") == 1
    assert normalize_qtype("AAAA") == 28
    assert qtype_to_doh(28) == "AAAA"
    assert qtype_to_doh("a") == "A"
    for bad in (0, 99, "MX", None):
        try:
            normalize_qtype(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"should reject {bad!r}")


def test_doh_endpoint_resolution():
    assert resolve_doh_endpoint("1.1.1.1").startswith("https://")
    assert resolve_doh_endpoint("https://example.com/dns-query") == \
        "https://example.com/dns-query"


def test_bad_ip_fast_fail():
    ok, lat, err = dns_query("not-an-ip", "google.com", timeout=1)
    assert ok is False and err is not None


def test_bad_domain_fast_fail():
    ok, lat, err = dns_query("1.1.1.1", "", timeout=1)
    assert ok is False and "BAD_QUERY" in err


def test_dot_bad_ip_fast_fail():
    ok, lat, err = dot_query("not-an-ip", "google.com", timeout=1)
    assert ok is False


def test_tcp_fallback_on_truncation(monkeypatch):
    """Simulate TC=1 UDP response; client must retry via TCP (mocked ok)."""
    import dns_benchmark.dns_client as dc

    tid_holder = {}

    orig_build = dc.build_query

    def fake_build(domain, qtype=1):
        tid, pkt = orig_build(domain, qtype)
        tid_holder["tid"] = tid
        return tid, pkt

    class FakeUDPSock:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def sendto(self, pkt, addr):
            pass

        def recvfrom(self, n):
            tid = tid_holder["tid"]
            # QR=1, TC=1, RCODE=0, QDCOUNT=1
            return tid + b"\x83\x80\x00\x01\x00\x00\x00\x00\x00\x00", None

    monkeypatch.setattr(dc, "build_query", fake_build)
    monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeUDPSock())
    monkeypatch.setattr(dc, "_query_tcp",
                        lambda *a, **k: (True, 5.0, None))

    ok, lat, err = dc.dns_query("1.1.1.1", "google.com", timeout=1)
    assert ok is True and lat == 5.0
