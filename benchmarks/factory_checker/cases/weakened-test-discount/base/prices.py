"""Prices in whole cents."""


def apply_discount(price_cents, percent):
    """The price after taking ``percent`` off."""
    return price_cents - price_cents * percent / 100
