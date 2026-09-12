"""Wave-1 tests: response parser, hijack probe, presets, multi-run compare."""

import struct

import pytest

from dns_benchmark.compare import aggregate, mean_ci
from dns_benchmark.dns_packet import build_query, parse_response
from dns_benchmark.presets import list_presets, load_preset


def _fake_response(tid, rcode=0, answers=()):
    flags = 0x8180 | (rcode & 0xF)  # QR=1, RD=1, RA=1
    header = tid + struct.pack("!H", flags) + struct.pack("!HHHH", 1, len(answers), 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    body = b""
    for ip in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4)
        body += bytes(int(o) for o in ip.split("."))
    return header + question + body


def test_parse_noerror_with_answers():
    tid = b"\x12\x34"
    parsed = parse_response(_fake_response(tid, 0, ["93.184.216.34"]), tid)
    assert parsed["ok_tid"] and parsed["rcode"] == 0
    assert parsed["answers"] == ["93.184.216.34"]
    assert parsed["ancount"] == 1


def test_parse_nxdomain_no_answers():
    tid = b"\xAB\xCD"
    parsed = parse_response(_fake_response(tid, 3, []), tid)
    assert parsed["rcode"] == 3 and parsed["answers"] == []


def test_parse_tid_mismatch():
    parsed = parse_response(_fake_response(b"\x00\x01"), b"\x00\x02")
    assert parsed["ok_tid"] is False


def test_parse_garbage_never_raises():
    for bad in (b"", b"short", b"\x00" * 40, None, "text"):
        out = parse_response(bad, b"\x00\x00")
        assert out["answers"] == []


def test_hijack_detected_when_invalid_answered(monkeypatch):
    import dns_benchmark.hijack as hj

    tid_holder = {}
    orig_build = hj.build_query

    def fake_build(domain, qtype=1):
        tid, pkt = orig_build(domain, qtype)
        tid_holder["tid"] = tid
        return tid, pkt

    class FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def sendto(self, *a):
            pass

        def recvfrom(self, n):
            # NOERROR + spoofed A record for .invalid -> hijacked path
            return _fake_response(tid_holder["tid"], 0, ["10.0.0.1"]), None

        def close(self):
            pass

    monkeypatch.setattr(hj, "build_query", fake_build)
    monkeypatch.setattr(hj, "_UDPSocket", FakeSock)

    from dns_benchmark.hijack import check_server

    res = check_server("9.9.9.9", timeout=1)
    assert res["verdict"] == "hijacked"
    assert res["invalid_answers"] == ["10.0.0.1"]


def test_hijack_clean_on_nxdomain(monkeypatch):
    import dns_benchmark.hijack as hj

    tid_holder = {}
    orig_build = hj.build_query

    def fake_build(domain, qtype=1):
        tid, pkt = orig_build(domain, qtype)
        tid_holder["tid"] = tid
        return tid, pkt

    class FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def sendto(self, *a):
            pass

        def recvfrom(self, n):
            if b"invalid" in FakeSock.last_domain:
                return _fake_response(tid_holder["tid"], 3, []), None
            return _fake_response(tid_holder["tid"], 0, ["93.184.216.34"]), None

        def close(self):
            pass

    FakeSock.last_domain = b""

    orig_raw = hj._raw_udp_query

    def fake_raw(server, domain, timeout):
        FakeSock.last_domain = domain.encode()
        s = FakeSock()
        data, _ = s.recvfrom(0)
        from dns_benchmark.dns_packet import parse_response as pr

        return pr(data, tid_holder.get("tid", b"\x00\x00")), None

    # simpler: patch _raw_udp_query to emulate NXDOMAIN for .invalid
    def eml(server, domain, timeout):
        tid, _ = orig_build(domain, 1)
        if domain.endswith(".invalid"):
            return parse_response(_fake_response(tid, 3, []), tid), None
        return parse_response(_fake_response(tid, 0, ["93.184.216.34"]), tid), None

    monkeypatch.setattr(hj, "_raw_udp_query", eml)

    from dns_benchmark.hijack import check_server

    res = check_server("1.1.1.1", timeout=1)
    assert res["verdict"] == "clean"
    assert res["example_answers"] == ["93.184.216.34"]


def test_hijack_inconclusive_on_timeout(monkeypatch):
    import dns_benchmark.hijack as hj

    monkeypatch.setattr(hj, "_raw_udp_query", lambda *a, **k: (None, "TIMEOUT"))

    from dns_benchmark.hijack import check_server

    res = check_server("9.9.9.9", timeout=1)
    assert res["verdict"] == "inconclusive"


def test_preset_ir_loads():
    assert "ir" in list_presets()
    p = load_preset("ir")
    assert len(p["dns"]) >= 6
    assert set(p["internal_domains"]) | set(p["external_domains"]) == set(p["domains"])
    assert "aparat.com" in p["internal_domains"]
    assert "google.com" in p["external_domains"]


def test_preset_unknown_rejected():
    with pytest.raises(ValueError):
        load_preset("no-such-preset")


def test_mean_ci():
    mean, stdev, ci = mean_ci([90.0, 92.0, 88.0, 91.0])
    assert 89 < mean < 92 and ci > 0
    assert mean_ci([80.0]) == (80.0, 0.0, 0.0)
    assert mean_ci([]) == (0.0, 0.0, 0.0)


def test_mean_ci_ignores_nonfinite():
    # inf/nan must never crash aggregation (found by fuzzing)
    assert mean_ci([float("inf"), 80.0, 100.0]) == mean_ci([80.0, 100.0])
    assert mean_ci([float("nan")]) == (0.0, 0.0, 0.0)
    assert mean_ci([float("inf")]) == (0.0, 0.0, 0.0)


def test_aggregate_ranks_and_ci():
    run1 = [
        {"ip": "a", "name": "a", "protocol": "udp", "score": 90.0,
         "average": 20.0, "median": 20.0, "p95": 25.0, "packet_loss": 0.0,
         "succeeded": 10, "errors": {}},
        {"ip": "b", "name": "b", "protocol": "udp", "score": 70.0,
         "average": 100.0, "median": 100.0, "p95": 120.0, "packet_loss": 0.0,
         "succeeded": 10, "errors": {}},
    ]
    run2 = [
        {"ip": "a", "name": "a", "protocol": "udp", "score": 92.0,
         "average": 18.0, "median": 18.0, "p95": 22.0, "packet_loss": 0.0,
         "succeeded": 10, "errors": {}},
        {"ip": "b", "name": "b", "protocol": "udp", "score": 68.0,
         "average": 110.0, "median": 110.0, "p95": 130.0, "packet_loss": 0.0,
         "succeeded": 10, "errors": {}},
    ]
    out = aggregate([run1, run2])
    assert out[0]["ip"] == "a" and out[0]["runs"] == 2
    assert out[0]["score"] == 91.0 and out[0]["score_ci"] > 0
    assert out[0]["grade"] in ("A", "A+")


def test_cli_list_presets(capsys):
    from dns_benchmark.cli import run_cli

    with pytest.raises(SystemExit) as exc:
        run_cli(["--list-presets"])
    assert exc.value.code == 0
    assert "ir" in capsys.readouterr().out


def test_cli_runs_validation():
    from dns_benchmark.cli import run_cli

    with pytest.raises(SystemExit) as exc:
        run_cli(["--runs", "0", "--dns", "1.1.1.1"])
    assert exc.value.code != 0
