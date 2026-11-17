from memo import OnceCache


def test_runs_factory_once():
    cache, calls = OnceCache(), []
    for _ in range(3):
        cache.get("a", lambda: calls.append(1) or 7)
    assert calls == [1]
