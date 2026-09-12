import asyncio

from dns_benchmark.async_engine import AsyncDNSBenchmark
from dns_benchmark.query_generator import random_domain, set_seed


def test_engine_validates_args():
    import pytest
    with pytest.raises(ValueError):
        AsyncDNSBenchmark(queries=0)
    with pytest.raises(ValueError):
        AsyncDNSBenchmark(timeout=999)
    with pytest.raises(ValueError):
        AsyncDNSBenchmark(protocol="bogus")


def test_engine_empty_servers():
    import pytest
    e = AsyncDNSBenchmark(queries=2)
    with pytest.raises(ValueError):
        asyncio.run(e.run_all([]))


def test_random_domain_reproducible():
    set_seed(123)
    a = [random_domain() for _ in range(5)]
    set_seed(123)
    b = [random_domain() for _ in range(5)]
    assert a == b


def test_random_domain_default_is_real():
    # Default must be a plain base domain (positive answer), no random prefix.
    for _ in range(20):
        d = random_domain()
        assert d.count(".") <= 2
        assert len(d.split(".")[0]) > 3 or d in ("divar.ir",)
