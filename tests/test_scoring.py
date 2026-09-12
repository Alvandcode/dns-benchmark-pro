from dns_benchmark.scoring import DNSScore, grade
from dns_benchmark.statistics import DNSStatistics


def test_full_loss_scores_zero():
    s = DNSStatistics([], 10)
    assert DNSScore(s).calculate() == 0.0


def test_uses_p95_tail_penalty():
    # Same average (50ms) but different tail: p95 must penalize the jittery one.
    stable = DNSStatistics([50.0] * 20, 20)
    jittery = DNSStatistics([40.0] * 18 + [140.0, 140.0], 20)
    assert abs(jittery.average - stable.average) < 0.01
    assert jittery.p95 > stable.p95
    assert DNSScore(jittery).calculate() < DNSScore(stable).calculate()


def test_grade_bands():
    assert grade(97) == "A+"
    assert grade(92) == "A"
    assert grade(85) == "B"
    assert grade(70) == "C"
    assert grade(50) == "D"
    assert grade(10) == "F"
    assert grade(0) == "F"
