import pytest

from dns_benchmark.advisor import recommend
from dns_benchmark.exporter import export_csv, export_json


def test_recommend_empty_raises():
    with pytest.raises(ValueError):
        recommend([])


def test_recommend_warns_when_all_bad():
    out = recommend([{"ip": "1.1.1.1", "score": 5.0, "packet_loss": 100.0}])
    assert out["recommended"] == "1.1.1.1"
    assert "warning" in out


def test_export_empty_raises(tmp_path):
    with pytest.raises(ValueError):
        export_csv([], tmp_path / "a.csv")
    with pytest.raises(ValueError):
        export_json([], tmp_path / "a.json")


def test_dashboard_escapes_xss(tmp_path):
    from dns_benchmark.dashboard import generate_html_report

    evil = [{"ip": "<script>alert(1)</script>", "score": 99,
             "grade": "A+", "average": 1, "median": 1, "p95": 1, "packet_loss": 0}]
    f = generate_html_report(evil, tmp_path / "r.html")
    content = f.read_text(encoding="utf-8")
    assert "<script>" not in content
    assert "&lt;script&gt;" in content
