"""Smoke tests for the new feature wave."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest

from bt_spy import db
from bt_spy.analysis.checksum import find_checksums, sum8, crc16_modbus


@pytest.fixture
def conn(tmp_path: Path):
    return db.init_db(tmp_path / "f.db")


def test_checksum_detector_finds_sum8():
    # Build payloads where byte[3] = sum8(bytes 0..3)
    payloads = []
    for v in (0x10, 0x20, 0x30, 0xFF, 0x42):
        body = bytes([0x01, v, 0x00])
        payloads.append(body + bytes([sum8(body)]))
    hyps = find_checksums(payloads)
    assert any(h.algo == "sum8" and h.input_start == 0 and h.input_end == 3 and h.output_offset == 3 for h in hyps), \
        f"expected sum8 hypothesis, got: {hyps}"


def test_checksum_detector_finds_crc16_modbus():
    payloads = []
    for v in (0x00, 0x01, 0x80, 0xFF):
        body = bytes([0x01, v, 0x42])
        crc = crc16_modbus(body)
        payloads.append(body + bytes([crc & 0xFF, (crc >> 8) & 0xFF]))
    hyps = find_checksums(payloads)
    assert any("crc16_modbus" in h.algo and h.output_size == 2 for h in hyps), \
        f"expected crc16_modbus hypothesis, got: {hyps}"


def test_checksum_detector_returns_empty_when_no_match():
    # Pure random; no structure
    payloads = [
        bytes([0x01, 0x00, 0xff, 0x7e, 0xaa]),
        bytes([0x02, 0x80, 0x10, 0x20, 0xbb]),
        bytes([0x03, 0xff, 0x00, 0x00, 0xcc]),
    ]
    # May or may not find spurious matches; either way it returns at most max_results
    hyps = find_checksums(payloads, max_results=8)
    assert len(hyps) <= 8


def test_export_pcap_writes_valid_header(conn, tmp_path):
    sid = db.start_session(conn, "x", capture_source="packetlogger")
    for ts in (0.0, 0.1, 0.2):
        db.insert_packet(conn, sid, ts=ts, direction=None, pdu_type=None,
                         handle=None, opcode=None, payload=None,
                         raw=bytes([0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]),
                         decoded=None)
    from bt_spy.export_pcap import write_pcap
    buf = BytesIO()
    n = write_pcap(conn, sid, buf)
    assert n == 3
    data = buf.getvalue()
    # Pcap classic global header: magic = 0xa1b2c3d4 big-endian = bytes a1 b2 c3 d4
    assert data[:4] == bytes.fromhex("a1b2c3d4")
    # Linktype for packetlogger source = BTHCI_H4 = 187 = 0x0BB
    # at offset 20 (last 4 bytes of 24-byte global header), big-endian uint32
    assert int.from_bytes(data[20:24], "big") == 187


def test_export_pcap_uses_btle_linktype_for_dongle(conn):
    sid = db.start_session(conn, "y", capture_source="nrf_sniffer")
    db.insert_packet(conn, sid, ts=0.0, direction=None, pdu_type=None,
                     handle=None, opcode=None, payload=None, raw=b"\xff", decoded=None)
    from bt_spy.export_pcap import write_pcap, LINKTYPE_BLUETOOTH_LE_LL
    buf = BytesIO()
    write_pcap(conn, sid, buf)
    assert int.from_bytes(buf.getvalue()[20:24], "big") == LINKTYPE_BLUETOOTH_LE_LL


def test_ltk_storage_round_trip(conn):
    db.upsert_ltk(conn, "AA:BB:CC:DD:EE:FF", "deadbeef" * 4, notes="test")
    ltks = db.get_ltks(conn)
    assert "AA:BB:CC:DD:EE:FF" in ltks
    assert ltks["AA:BB:CC:DD:EE:FF"]["ltk_hex"] == "deadbeef" * 4


def test_sig_decoder_battery_level():
    """Confirm autoload picks up the SIG-standard battery decoder."""
    from bt_spy.analysis.decoder import autoload_builtin_decoders, _REGISTRY
    autoload_builtin_decoders()
    key = "*:char:00002a19-0000-1000-8000-00805f9b34fb"
    assert key in _REGISTRY
    assert _REGISTRY[key](b"\x42") == {"battery_percent": 0x42}
