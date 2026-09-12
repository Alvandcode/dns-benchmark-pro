from dns_benchmark.statistics import DNSStatistics


def test_p95_sorted():
    s = DNSStatistics([100, 20, 30, 40, 50, 60, 70, 80, 90, 10], 10)
    assert s.p95 == 100.0


def test_p95_two_values():
    assert DNSStatistics([10, 100], 2).p95 == 100.0
    assert DNSStatistics([100, 10], 2).p95 == 100.0


def test_p95_empty():
    assert DNSStatistics([], 10).p95 == 0.0


def test_packet_loss_zero_total_no_crash():
    assert DNSStatistics([], 0).packet_loss == 0.0
    assert DNSStatistics([10.0], 0).packet_loss == 0.0


def test_packet_loss_values():
    assert DNSStatistics([1, 2], 4).packet_loss == 50.0
    assert DNSStatistics([], 10).packet_loss == 100.0
    assert DNSStatistics([1], 1).packet_loss == 0.0
