"""Mutation strategies are pure — easy to unit test without a real BLE device."""

from __future__ import annotations

import pytest

from bt_spy.replay.engine import apply_mutation


def test_set_byte():
    assert apply_mutation(b"\x01\x00\xff", {"strategy": "set_byte", "offset": 1, "value": 0x80}) == b"\x01\x80\xff"


def test_xor_byte():
    assert apply_mutation(b"\x01\xff", {"strategy": "xor_byte", "offset": 1, "mask": 0x0f}) == b"\x01\xf0"


def test_increment_byte_default_step():
    assert apply_mutation(b"\x05", {"strategy": "increment_byte", "offset": 0}) == b"\x06"


def test_increment_byte_wraps():
    assert apply_mutation(b"\xff", {"strategy": "increment_byte", "offset": 0}) == b"\x00"


def test_replace():
    assert apply_mutation(b"\x01", {"strategy": "replace", "hex": "deadbeef"}) == b"\xde\xad\xbe\xef"


def test_unknown_strategy_raises():
    with pytest.raises(ValueError):
        apply_mutation(b"\x00", {"strategy": "nope"})


def test_no_mutation_passthrough():
    assert apply_mutation(b"\x01\x02", None) == b"\x01\x02"
