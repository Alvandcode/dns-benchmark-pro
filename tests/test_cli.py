from dns_benchmark.cli import build_parser, main, run_cli
from dns_benchmark.query_generator import set_custom_domains


def test_cli_defaults():
    args = build_parser().parse_args([])
    assert args.queries == 10 and args.protocol == "udp" and args.qtype == "A"


def test_cli_rejects_bad_qtype(capsys):
    try:
        run_cli(["--qtype", "MX"])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("should exit on bad qtype")


def test_cli_rejects_zero_queries():
    try:
        run_cli(["--queries", "0"])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("should exit on queries=0")


def test_main_total_failure_exit_code(monkeypatch):
    import dns_benchmark.cli as cli

    monkeypatch.setattr(
        cli, "run_cli",
        lambda argv=None: [{"ip": "1.1.1.1", "packet_loss": 100.0}],
    )
    assert main([]) == 2


def test_main_empty_exit_code(monkeypatch):
    import dns_benchmark.cli as cli

    monkeypatch.setattr(cli, "run_cli", lambda argv=None: [])
    assert main([]) == 1


def test_custom_domains_pool():
    set_custom_domains(["example.com"])
    try:
        from dns_benchmark.query_generator import random_domain

        assert random_domain() == "example.com"
    finally:
        set_custom_domains(None)


def test_exporter_flattens_errors(tmp_path):
    from dns_benchmark.exporter import export_csv

    rows = [{"ip": "1.1.1.1", "score": 1, "errors": {"TIMEOUT": 2, "INVALID": 1}}]
    f = export_csv(rows, tmp_path / "r.csv")
    text = f.read_text(encoding="utf-8-sig")
    assert "TIMEOUTx2" in text and "INVALIDx1" in text
