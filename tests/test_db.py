"""Smoke tests for the DB layer — schema, insert, query, diff."""

from __future__ import annotations

from pathlib import Path

import pytest

from bt_spy import db


@pytest.fixture
def conn(tmp_path: Path):
    return db.init_db(tmp_path / "test.db")


def test_schema_initialised(conn):
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )]
    assert {"sessions", "packets", "annotations", "protocol_entries", "replays", "meta"} <= set(tables)


def test_session_lifecycle(conn):
    sid = db.start_session(conn, "baseline", notes="idle")
    assert sid > 0
    db.end_session(conn, sid)
    row = conn.execute("SELECT ended_at FROM sessions WHERE id=?", (sid,)).fetchone()
    assert row["ended_at"] is not None


def test_packet_insert_and_query(conn):
    sid = db.start_session(conn, "s")
    db.insert_packet(conn, sid, ts=0.1, direction="central->peripheral",
                     pdu_type="ATT_WRITE_REQ", handle=36, opcode=0x12,
                     payload=b"\x01\x00", raw=b"\xff\x01\x00", decoded={"summary": "ok"})
    db.insert_packet(conn, sid, ts=0.2, direction="central->peripheral",
                     pdu_type="ATT_WRITE_REQ", handle=36, opcode=0x12,
                     payload=b"\x01\x01", raw=b"\xff\x01\x01", decoded={"summary": "ok"})
    rows = db.get_packets(conn, sid, handle=36)
    assert len(rows) == 2
    assert bytes(rows[0]["payload"]) == b"\x01\x00"


def test_diff_sessions_finds_new(conn):
    base = db.start_session(conn, "baseline")
    db.insert_packet(conn, base, ts=0, direction="adv", pdu_type="ADV_IND",
                     handle=None, opcode=None, payload=None, raw=b"\xaa", decoded=None)
    cand = db.start_session(conn, "do")
    db.insert_packet(conn, cand, ts=0, direction="adv", pdu_type="ADV_IND",
                     handle=None, opcode=None, payload=None, raw=b"\xaa", decoded=None)
    db.insert_packet(conn, cand, ts=0.1, direction="central->peripheral",
                     pdu_type="ATT_WRITE_REQ", handle=36, opcode=0x12,
                     payload=b"\x01\x80", raw=b"\xff\x01\x80", decoded=None)
    out = db.diff_sessions(conn, base, cand)
    assert out["new_packet_count"] == 1
    assert out["new_packets"][0]["handle"] == 36


def test_protocol_entry_upsert(conn):
    eid = db.upsert_protocol_entry(
        conn, device_name="MiSmartLight", handle=36,
        direction="central->peripheral", name="power_command",
        structure=[{"offset": 0, "length": 1, "name": "cmd"}],
        decoder_py="def decode(payload): return {'on': bool(payload[1])}",
        confidence=0.9, notes="confirmed via replay",
    )
    assert eid > 0
    # Upsert again — same composite key, new confidence
    eid2 = db.upsert_protocol_entry(
        conn, device_name="MiSmartLight", handle=36,
        direction="central->peripheral", name="power_command",
        structure=[{"offset": 0, "length": 1, "name": "cmd"}],
        confidence=0.95,
    )
    rows = list(conn.execute("SELECT * FROM protocol_entries"))
    assert len(rows) == 1
    assert rows[0]["confidence"] == 0.95
