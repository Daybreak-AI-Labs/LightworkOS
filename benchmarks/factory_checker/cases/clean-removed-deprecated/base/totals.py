"""Order totals."""


def total(items):
    """The sum of price * quantity over (price, quantity) pairs."""
    return sum(price * qty for price, qty in items)


def legacy_total(prices):
    """Deprecated: use total(). The sum of a list of prices."""
    return sum(prices)
