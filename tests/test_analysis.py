"""Tests for analysis: handle_summary, infer_structure."""

from __future__ import annotations

from pathlib import Path

import pytest

from bt_spy import db
from bt_spy.analysis import diff as diffmod


@pytest.fixture
def conn(tmp_path: Path):
    return db.init_db(tmp_path / "a.db")


def test_handle_summary_counts_uniques(conn):
    sid = db.start_session(conn, "s")
    for p in (b"\x01\x00\xff", b"\x01\x80\xff", b"\x01\x80\xff"):
        db.insert_packet(conn, sid, ts=0.0, direction="central->peripheral",
                         pdu_type="ATT_WRITE_REQ", handle=36, opcode=0x12,
                         payload=p, raw=p, decoded=None)
    summary = diffmod.handle_summary(conn, sid)
    assert len(summary) == 1
    s = summary[0]
    assert s.handle == 36
    assert s.count == 3
    assert s.unique_payloads == 2
    # Byte 0 constant, byte 2 constant, byte 1 varies → variability[0]==0, [2]==0, [1]>0
    assert s.byte_variability[0] == 0.0
    assert s.byte_variability[2] == 0.0
    assert s.byte_variability[1] > 0.0


def test_infer_structure_segments():
    payloads = [b"\x01\x00\xff\x7e", b"\x01\x80\xff\x7e", b"\x01\xff\xff\x7e"]
    segs = diffmod.infer_structure(payloads)
    # Expect at least: a constant prefix, a high-variance middle, a constant suffix.
    kinds = [s["kind"] for s in segs]
    assert "constant" in kinds
    assert any(k in ("high_variance", "low_variance", "near_constant") for k in kinds)
