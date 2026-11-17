from config import Config


def test_get_and_set():
    cfg = Config(a=1)
    cfg.set("b", 2)
    assert cfg.get("a") == 1 and cfg.get("b") == 2 and cfg.get("c", 3) == 3
