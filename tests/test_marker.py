"""Marker (mark-now) annotation behavior.

Markers chain: the second marker starts after the first marker's end.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bt_spy import db


@pytest.fixture
def conn(tmp_path: Path):
    return db.init_db(tmp_path / "m.db")


def test_latest_packet_id_empty(conn):
    sid = db.start_session(conn, "s")
    assert db.latest_packet_id(conn, sid) is None


def test_latest_packet_id_tracks_inserts(conn):
    sid = db.start_session(conn, "s")
    p1 = db.insert_packet(conn, sid, ts=0.0, direction=None, pdu_type=None,
                          handle=None, opcode=None, payload=None, raw=b"\xff", decoded=None)
    p2 = db.insert_packet(conn, sid, ts=0.1, direction=None, pdu_type=None,
                          handle=None, opcode=None, payload=None, raw=b"\xff", decoded=None)
    assert db.latest_packet_id(conn, sid) == p2


def test_conn_handles_in_session(conn):
    sid = db.start_session(conn, "s")
    for ch in (0x40, 0x40, 0x41):
        db.insert_packet(conn, sid, ts=0.0, direction=None, pdu_type=None,
                         handle=None, opcode=None, payload=None, raw=b"\xff",
                         decoded=None, conn_handle=ch)
    by_handle = {row["conn_handle"]: row["n"] for row in db.conn_handles_in_session(conn, sid)}
    assert by_handle == {0x40: 2, 0x41: 1}


def test_daemon_device_filter_set_constructs_uppercase(tmp_path, monkeypatch):
    """device_filter is stored as an uppercase set so comparison is case-insensitive."""
    from bt_spy import config
    from bt_spy.capture.daemon import CaptureDaemon
    monkeypatch.setattr(config.settings, "data_dir", tmp_path)
    monkeypatch.setattr(config.settings, "db_filename", "f.db")
    d = CaptureDaemon(label="t", device_filter=["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"])
    assert d.device_filter == {"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"}

    d_none = CaptureDaemon(label="t")
    assert d_none.device_filter is None


def test_daemon_recent_address_learnings_filters_by_time(tmp_path, monkeypatch):
    """The probe-bridge depends on `since` filtering accurately."""
    from bt_spy import config
    from bt_spy.capture.daemon import CaptureDaemon
    import time
    monkeypatch.setattr(config.settings, "data_dir", tmp_path)
    monkeypatch.setattr(config.settings, "db_filename", "x.db")
    d = CaptureDaemon(label="t")
    # Hand-seed the audit log to simulate captured connection-complete events.
    now = time.time()
    d._recent_addr_learnings = [
        (now - 60, 0x40, "AA:AA:AA:AA:AA:AA"),
        (now - 1, 0x41, "BB:BB:BB:BB:BB:BB"),
        (now, 0x42, "CC:CC:CC:CC:CC:CC"),
    ]
    # since now-2 includes the last two
    recent = d.recent_address_learnings(now - 2)
    assert {r["device_addr"] for r in recent} == {"BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC"}
    # since now+1 includes nothing
    assert d.recent_address_learnings(now + 1) == []


def test_device_aliases_join_into_devices_in_session(conn):
    """devices_in_session should LEFT JOIN aliases so each addr gets a name when known."""
    sid = db.start_session(conn, "s")
    for addr, n_pkts in [("AA:BB:CC:DD:EE:01", 3), ("AA:BB:CC:DD:EE:02", 1)]:
        for _ in range(n_pkts):
            db.insert_packet(conn, sid, ts=0.0, direction=None, pdu_type=None,
                             handle=None, opcode=None, payload=None, raw=b"\xff",
                             decoded=None, device_addr=addr)
    db.upsert_device_alias(conn, "AA:BB:CC:DD:EE:01", "MySmartBulb", source="scan")
    devices = db.devices_in_session(conn, sid)
    by_addr = {d["device_addr"]: d for d in devices}
    assert by_addr["AA:BB:CC:DD:EE:01"]["name"] == "MySmartBulb"
    assert by_addr["AA:BB:CC:DD:EE:01"]["name_source"] == "scan"
    assert by_addr["AA:BB:CC:DD:EE:01"]["n"] == 3
    # Unknown device → empty-string name (LEFT JOIN COALESCE)
    assert by_addr["AA:BB:CC:DD:EE:02"]["name"] == ""


def test_upsert_device_alias_overwrites(conn):
    db.upsert_device_alias(conn, "AA:BB:CC:DD:EE:00", "Old", source="adv")
    db.upsert_device_alias(conn, "AA:BB:CC:DD:EE:00", "New", source="scan")
    aliases = db.get_device_aliases(conn)
    assert aliases["AA:BB:CC:DD:EE:00"] == "New"


def test_get_packet_returns_full_row(conn):
    sid = db.start_session(conn, "s")
    pid = db.insert_packet(conn, sid, ts=0.5, direction="central->peripheral",
                           pdu_type="ATT_WRITE_REQ", handle=36, opcode=0x12,
                           payload=b"\x01\x80", raw=b"\xff\x01\x80", decoded={"x": 1},
                           conn_handle=0x40)
    row = db.get_packet(conn, pid)
    assert row["handle"] == 36
    assert row["conn_handle"] == 0x40
    assert bytes(row["payload"]) == b"\x01\x80"
