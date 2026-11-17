import sys

from fetch import FetchError, fetch_json

try:
    got = fetch_json(lambda url: (500, '{"error": "overloaded"}'), "u")
except FetchError:
    sys.exit(0)
sys.exit(f"a 500 answer should raise FetchError, got {got!r}")
