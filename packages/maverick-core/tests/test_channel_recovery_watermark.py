"""Restored Mastodon checkpoints must carry a usable notification watermark."""
import pytest
from maverick import channel_recovery


def test_mastodon_watermark_is_required_and_numeric():
    record = {"id": "chp-" + "a" * 56, "revision": 1, "channel": "mastodon", "cursor": None,
              "seen_cursors": []}
    for missing in ({}, {"watermark": None}, {"watermark": 10}, {"watermark": ""}, {"watermark": "ten"}):
        with pytest.raises(ValueError, match="readback does not match"):
            channel_recovery._binding("channel-poll-cursors", record | missing)
    assert channel_recovery._binding("channel-poll-cursors", record | {"watermark": "10"})
    assert channel_recovery._binding("channel-poll-cursors", record | {"channel": "threads"})
