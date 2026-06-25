"""Tests for the .pklg parser + offline import.

Build synthetic .pklg files in-memory rather than depending on real Apple captures.
This is enough to exercise the format-handling code and prove records flow through
to the DB with the right shape.
"""

from __future__ import annotations

import io
import struct
import time
from pathlib import Path

import pytest

from bt_spy import db
from bt_spy.capture import packetlogger as pkl


def _pklg_record(type_code: int, payload: bytes, ts_sec: int = 100, ts_usec: int = 500_000) -> bytes:
    """Pack one .pklg record per Apple's format.

    Apple's length field excludes itself: length = ts(8) + type(1) + payload.
    So the total record on disk is 4 + length bytes.
    """
    length = 9 + len(payload)
    return struct.pack(">IIIB", length, ts_sec, ts_usec, type_code) + payload


def test_parse_minimal_command_record():
    # HCI Reset command: opcode=0x0C03, no params. Type 0x00 = HCI Command.
    cmd = bytes.fromhex("030c00")  # opcode_lo opcode_hi param_len
    buf = io.BytesIO(_pklg_record(0x00, cmd))
    records = list(pkl.iter_pklg_records(buf))
    assert len(records) == 1
    r = records[0]
    assert r.type_code == 0x00
    assert r.payload == cmd
    assert r.ts == 100.5


def test_parse_multiple_records_and_truncated_tail_is_safe():
    r1 = _pklg_record(0x00, b"\x03\x0c\x00")             # HCI Reset
    r2 = _pklg_record(0x01, b"\x0e\x04\x01\x03\x0c\x00")  # Cmd complete event
    truncated = r1[:7]  # cut off mid-header
    buf = io.BytesIO(r1 + r2 + truncated)
    records = list(pkl.iter_pklg_records(buf))
    assert len(records) == 2
    assert records[0].type_code == 0x00
    assert records[1].type_code == 0x01


def test_record_to_frame_adds_h4_indicator():
    rec = pkl.PklgRecord(ts=1.0, type_code=0x02, payload=b"\xAA\xBB")  # ACL Send
    frame = pkl.pklg_record_to_frame(rec)
    assert frame is not None
    assert frame.raw == b"\x02\xAA\xBB"  # H4 ACL indicator + payload
    assert frame.decoded["direction_hint"] == "host->controller"


def test_unknown_type_code_returns_none():
    rec = pkl.PklgRecord(ts=0.0, type_code=0x77, payload=b"")
    assert pkl.pklg_record_to_frame(rec) is None


def test_iter_pklg_file_round_trip(tmp_path):
    # Two records: a command and an event, written to disk and read back.
    f = tmp_path / "t.pklg"
    f.write_bytes(_pklg_record(0x00, b"\x03\x0c\x00") + _pklg_record(0x01, b"\x0e\x04\x01\x03\x0c\x00"))
    frames = list(pkl.iter_pklg_file(f))
    assert len(frames) == 2
    # First is H4 command, second H4 event
    assert frames[0].raw[0] == 0x01
    assert frames[1].raw[0] == 0x04


def test_addr_str_normalizes_bytes_and_strings():
    from bt_spy.capture.parser import _addr_str
    # 6 raw bytes (little-endian as scapy emits) → uppercase MAC
    assert _addr_str(b"\xff\xee\xdd\xcc\xbb\xaa") == "AA:BB:CC:DD:EE:FF"
    # Already-formatted lowercase → uppercased
    assert _addr_str("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    # Wrong-shape bytes → None
    assert _addr_str(b"\x01\x02") is None
    assert _addr_str(None) is None


def test_hci_decoder_extracts_conn_handle_and_att_write():
    """The HCI ACL frame's connection handle (link-layer) and the inner ATT handle (GATT)
    are distinct fields; both must be extracted independently."""
    from bt_spy.capture.parser import decode_hci
    att = bytes([0x12, 0x24, 0x00, 0x01, 0x80])           # ATT_WRITE_REQ to handle 0x0024
    l2cap = bytes([len(att), 0x00, 0x04, 0x00]) + att      # ATT CID = 0x0004
    acl_handle = 0x0040                                    # link-layer conn handle
    acl_hdr = acl_handle.to_bytes(2, "little") + len(l2cap).to_bytes(2, "little")
    h4 = bytes([0x02]) + acl_hdr + l2cap
    res = decode_hci(h4, direction_hint="host->controller")
    assert res.handle == 0x0024, f"ATT handle wrong: {res.handle!r}"
    assert res.conn_handle == acl_handle, f"conn handle wrong: {res.conn_handle!r}"


def test_hci_decoder_extracts_att_write():
    """Synthesize an HCI ACL frame carrying an ATT_WRITE_REQ to handle 0x0024 and confirm decode."""
    from bt_spy.capture.parser import decode_hci
    # Layered build:
    #   ATT_WRITE_REQ (opcode 0x12, handle 0x0024, value bytes 01 80 ff 7e)
    att = bytes([0x12, 0x24, 0x00, 0x01, 0x80, 0xff, 0x7e])
    # L2CAP header: length=7 (LE), CID=0x0004 (ATT)
    l2cap = bytes([len(att), 0x00, 0x04, 0x00]) + att
    # HCI ACL header: connection_handle=0x0040, packet_boundary flags=0x2, broadcast=0x0; total_len=len(l2cap)
    acl_handle_flags = 0x2040  # little-endian: 0x40 then flags 0x20
    acl_hdr = acl_handle_flags.to_bytes(2, "little") + len(l2cap).to_bytes(2, "little")
    # HCI H4 indicator byte for ACL = 0x02
    h4 = bytes([0x02]) + acl_hdr + l2cap

    res = decode_hci(h4, direction_hint="host->controller")
    assert res.handle == 0x0024, f"expected handle 0x24, got {res.handle!r}"
    assert res.opcode == 0x12
    # scapy stores the trailing bytes as the value/data field
    assert res.payload == b"\x01\x80\xff\x7e", f"got {res.payload!r}"
    assert res.direction == "host->controller"
    assert res.pdu_type and res.pdu_type.startswith("ATT_")


def test_decode_frame_routes_by_linktype():
    """Verify decode_frame picks the HCI decoder when linktype is BTHCI_H4."""
    from bt_spy.capture.parser import (
        Frame, LINKTYPE_BLUETOOTH_HCI_H4, LINKTYPE_BLUETOOTH_LE_LL, decode_frame,
    )
    hci_frame = Frame(timestamp=0.0, linktype=LINKTYPE_BLUETOOTH_HCI_H4,
                      raw=b"\x04\x0e\x04\x01\x03\x0c\x00", decoded={"direction_hint": "controller->host"})
    res = decode_frame(hci_frame)
    # Should at least produce a layer breakdown, no decode_error
    assert "decode_error" not in res.summary
    # And linktype routing should NOT have called the BTLE decoder (which would mangle this)
    assert any(l.startswith("HCI_") for l in res.summary.get("layers", []))


def test_pklg_tail_streams_records_as_written(tmp_path):
    """Write records into a file from a background thread; tail in main thread; assert order + count."""
    import threading
    f = tmp_path / "live.pklg"
    f.touch()
    stop = threading.Event()
    written = [
        _pklg_record(0x00, b"\x03\x0c\x00"),
        _pklg_record(0x01, b"\x0e\x04\x01\x03\x0c\x00"),
        _pklg_record(0x00, b"\x03\x0c\x00"),
    ]

    def writer():
        # Write each record, sleep briefly between to simulate live capture.
        with open(f, "ab", buffering=0) as fh:
            for rec in written:
                fh.write(rec)
                fh.flush()
                time.sleep(0.02)
        # Give the reader a beat to drain then stop it.
        time.sleep(0.1)
        stop.set()

    t = threading.Thread(target=writer)
    t.start()
    frames = list(pkl.iter_pklg_tail(f, stop_event=stop, poll_interval_s=0.01))
    t.join()
    assert len(frames) == len(written), f"expected {len(written)} frames, got {len(frames)}"


def test_pklg_tail_errors_loudly_on_garbage_file(tmp_path):
    f = tmp_path / "junk.pklg"
    f.write_bytes(b"\xff" * 64)  # garbage — length field would be huge
    import threading
    import pytest as _pt
    with _pt.raises(ValueError):
        list(pkl.iter_pklg_tail(f, stop_event=threading.Event(), initial_wait_s=1.0))


def test_import_pklg_writes_session_and_packets(tmp_path, monkeypatch):
    from bt_spy import config
    monkeypatch.setattr(config.settings, "data_dir", tmp_path)
    monkeypatch.setattr(config.settings, "db_filename", "t.db")

    f = tmp_path / "x.pklg"
    f.write_bytes(
        _pklg_record(0x00, b"\x03\x0c\x00")              # HCI Reset cmd
        + _pklg_record(0x01, b"\x0e\x04\x01\x03\x0c\x00")  # Cmd complete event
        + _pklg_record(0x02, b"\x40\x20\x07\x00\x03\x00\x04\x00\x0a\x14\x00")  # ACL toward controller
    )

    from bt_spy.capture.daemon import import_pklg
    res = import_pklg(f, label="test_pklg")
    assert res["packet_count"] == 3
    sid = res["session_id"]

    conn = db.init_db()
    row = conn.execute("SELECT capture_source FROM sessions WHERE id=?", (sid,)).fetchone()
    assert row["capture_source"] == "packetlogger"
    n = conn.execute("SELECT COUNT(*) FROM packets WHERE session_id=?", (sid,)).fetchone()[0]
    assert n == 3
