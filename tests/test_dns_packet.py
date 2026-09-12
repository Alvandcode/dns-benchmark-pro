import pytest

from dns_benchmark.dns_packet import build_query, validate_response


def test_rejects_nxdomain():
    tid, _ = build_query("google.com")
    fake_nx = tid + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
    assert validate_response(fake_nx, tid) is False


def test_accepts_noerror():
    tid, _ = build_query("google.com")
    fake_ok = tid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    assert validate_response(fake_ok, tid) is True


def test_rejects_tid_mismatch():
    tid, _ = build_query("google.com")
    fake = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    assert validate_response(fake, tid) is False


@pytest.mark.parametrize("bad", ["", ".com", "a..b.com", "a" * 70 + ".com", "-bad.com"])
def test_rejects_bad_domains(bad):
    with pytest.raises(ValueError):
        build_query(bad)


def test_accepts_fqdn_trailing_dot():
    # Single trailing dot is valid FQDN form and must be accepted.
    tid, pkt = build_query("google.com.")
    assert len(pkt) > 12
    assert len(tid) == 2


def test_rejects_bad_qtype():
    with pytest.raises(ValueError):
        build_query("google.com", qtype=0)
    with pytest.raises(ValueError):
        build_query("google.com", qtype=70000)
