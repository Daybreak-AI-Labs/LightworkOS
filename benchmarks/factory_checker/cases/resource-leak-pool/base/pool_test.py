from pool import Pool, with_conn


def test_gives_the_connection_back():
    pool = Pool(2)
    assert with_conn(pool, lambda conn: 3) == 3
    assert pool.available == 2
