"""Seed a bt-spy DB with synthetic demo data — used to make screenshots
look realistic without committing real BD_ADDRs / device names to a public repo.

Usage:
    BTSPY_DATA_DIR=/tmp/bt-spy-screenshots .venv/bin/python scripts/seed_demo_data.py

Creates: 3 sessions, ~300 packets across them, a couple of device aliases,
two protocol entries, one annotation/marker, one replay row.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from bt_spy import db, config


def seed():
    config.settings.ensure_dirs()
    print(f"Seeding into {config.settings.db_path}")
    conn = db.init_db()

    # Wipe any existing demo content
    conn.execute("DELETE FROM packets")
    conn.execute("DELETE FROM annotations")
    conn.execute("DELETE FROM sessions")
    conn.execute("DELETE FROM device_aliases")
    conn.execute("DELETE FROM protocol_entries")
    conn.execute("DELETE FROM replays")

    # --- aliases ---
    db.upsert_device_alias(conn, "AA:BB:CC:11:22:33", "DemoBulb-A1B2", source="scan")
    db.upsert_device_alias(conn, "AA:BB:CC:44:55:66", "DemoSensor-3CD4", source="adv")
    db.upsert_device_alias(conn, "AA:BB:CC:77:88:99", "DemoSwitch-5EF6", source="user")

    # --- session 1: baseline (idle scan) ---
    s1 = db.start_session(conn, "baseline_idle", notes="No interaction; capture of ambient BLE traffic.",
                           capture_source="nrf_sniffer")
    t = 0.0
    for i, addr in enumerate(["AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66", "AA:BB:CC:77:88:99"]):
        for j in range(15):
            db.insert_packet(
                conn, s1, ts=t, direction="adv", pdu_type="BTLE_ADV_IND",
                handle=None, opcode=None, payload=None,
                raw=bytes([0xcd, 0x38, 0x00, 0x03, j, 0, 0, 0, 0x25, 30, 0, 0, 0, 0, 0, 0, 0,
                           0xd6, 0xbe, 0x89, 0x8e, 0x40, 0x18] + list(bytes.fromhex(addr.replace(":", "")))[::-1] + [0x02, 0x01, 0x06]),
                decoded={"raw_hex": "...","len": 30, "nordic_channel": 37 + (j % 3),
                         "nordic_rssi_dbm": -40 - (j % 20), "layers": ["BTLE", "BTLE_ADV", "BTLE_ADV_IND"]},
                device_addr=addr,
            )
            t += 0.015
    db.end_session(conn, s1)

    # --- session 2: tap_power_on ---
    s2 = db.start_session(conn, "tap_power_on",
                           notes="Tapped Power On in vendor app for DemoBulb.",
                           capture_source="pklg_tail")
    t = 0.0
    # baseline-like advertising
    for j in range(20):
        db.insert_packet(
            conn, s2, ts=t, direction="adv", pdu_type="BTLE_ADV_IND",
            handle=None, opcode=None, payload=None,
            raw=bytes([0xcd, 0x38, 0x00, 0x03]) + bytes(30),
            decoded={"layers": ["BTLE", "BTLE_ADV", "BTLE_ADV_IND"]},
            device_addr="AA:BB:CC:44:55:66",
        )
        t += 0.012
    # the interesting packet
    interesting_pid_start = db.insert_packet(
        conn, s2, ts=t, direction="central->peripheral",
        pdu_type="ATT_WRITE_REQ", handle=36, conn_handle=64, opcode=0x12,
        payload=bytes([0x01, 0x01, 0xff, 0x7e]),
        raw=bytes([0x02, 0x40, 0x20, 0x09, 0x00, 0x05, 0x00, 0x04, 0x00, 0x12, 0x24, 0x00, 0x01, 0x01, 0xff, 0x7e]),
        decoded={"layers": ["HCI_Hdr", "HCI_ACL_Hdr", "L2CAP_Hdr", "ATT_Hdr", "ATT_Write_Request"]},
        device_addr="AA:BB:CC:11:22:33",
    )
    t += 0.005
    # ack
    db.insert_packet(
        conn, s2, ts=t, direction="peripheral->central",
        pdu_type="ATT_WRITE_RSP", handle=36, conn_handle=64, opcode=0x13,
        payload=None,
        raw=bytes([0x02, 0x40, 0x20, 0x05, 0x00, 0x01, 0x00, 0x04, 0x00, 0x13]),
        decoded={"layers": ["HCI_Hdr", "HCI_ACL_Hdr", "L2CAP_Hdr", "ATT_Hdr", "ATT_Write_Response"]},
        device_addr="AA:BB:CC:11:22:33",
    )
    t += 0.01
    interesting_pid_end = db.insert_packet(
        conn, s2, ts=t, direction="peripheral->central",
        pdu_type="ATT_HANDLE_VALUE_NTF", handle=40, conn_handle=64, opcode=0x1B,
        payload=bytes([0x42]),
        raw=bytes([0x02, 0x40, 0x20, 0x06, 0x00, 0x02, 0x00, 0x04, 0x00, 0x1B, 0x28, 0x00, 0x42]),
        decoded={"layers": ["HCI_Hdr", "HCI_ACL_Hdr", "L2CAP_Hdr", "ATT_Hdr", "ATT_Handle_Value_Notification"]},
        device_addr="AA:BB:CC:11:22:33",
    )
    # annotation/marker over the interesting range
    db.add_annotation(conn, s2, interesting_pid_start, interesting_pid_end,
                      label="tap_power_on", notes="Vendor app's power-on command sequence.")
    db.end_session(conn, s2)

    # --- session 3: slide_brightness ---
    s3 = db.start_session(conn, "slide_brightness_0_to_255",
                           notes="Slid brightness from 0 to max in vendor app.",
                           capture_source="pklg_tail")
    t = 0.0
    for level in (0x00, 0x40, 0x80, 0xC0, 0xFF):
        db.insert_packet(
            conn, s3, ts=t, direction="central->peripheral",
            pdu_type="ATT_WRITE_REQ", handle=36, conn_handle=64, opcode=0x12,
            payload=bytes([0x02, level, 0xff, 0x7e]),
            raw=bytes([0x02, 0x40, 0x20, 0x09, 0x00, 0x05, 0x00, 0x04, 0x00, 0x12, 0x24, 0x00, 0x02, level, 0xff, 0x7e]),
            decoded={"layers": ["HCI_Hdr", "HCI_ACL_Hdr", "L2CAP_Hdr", "ATT_Hdr", "ATT_Write_Request"]},
            device_addr="AA:BB:CC:11:22:33",
        )
        t += 0.2
    db.end_session(conn, s3)

    # --- protocol entries ---
    db.upsert_protocol_entry(
        conn, device_name="DemoBulb", handle=36,
        char_uuid="0000fff1-0000-1000-8000-00805f9b34fb",
        direction="central->peripheral", name="power",
        structure=[{"offset": 0, "length": 1, "name": "cmd", "value": 1},
                   {"offset": 1, "length": 1, "name": "on", "encoding": "bool"},
                   {"offset": 2, "length": 2, "name": "tail", "value_hex": "ff7e"}],
        encoder_py="def encode(on):\n    return bytes([0x01, int(bool(on)), 0xff, 0x7e])",
        decoder_py="def decode(payload):\n    return {'on': bool(payload[1])}",
        confidence=0.95,
        notes="Confirmed via replay across 5 power-state changes.",
    )
    db.upsert_protocol_entry(
        conn, device_name="DemoBulb", handle=36,
        char_uuid="0000fff1-0000-1000-8000-00805f9b34fb",
        direction="central->peripheral", name="set_brightness",
        structure=[{"offset": 0, "length": 1, "name": "cmd", "value": 2},
                   {"offset": 1, "length": 1, "name": "level"},
                   {"offset": 2, "length": 2, "name": "tail", "value_hex": "ff7e"}],
        encoder_py="def encode(level):\n    return bytes([0x02, level & 0xff, 0xff, 0x7e])",
        decoder_py="def decode(payload):\n    return {'level': payload[1]}",
        confidence=0.9,
    )

    # one replay row
    db.record_replay(
        conn, session_id=s2, target_mac="AA:BB:CC:11:22:33",
        sent=[{"handle": 36, "char_uuid": "0000fff1-0000-1000-8000-00805f9b34fb",
               "payload_hex": "0101ff7e", "with_response": True}],
        response=[{"ts": time.time(), "kind": "write_ack", "handle": 36,
                   "char_uuid": "0000fff1-0000-1000-8000-00805f9b34fb",
                   "payload_hex": "0101ff7e"}],
        status="ok", error=None,
        started_at=time.time() - 1.0, ended_at=time.time(),
    )

    print(f"  3 sessions, {conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0]} packets")
    print(f"  {conn.execute('SELECT COUNT(*) FROM device_aliases').fetchone()[0]} aliases")
    print(f"  {conn.execute('SELECT COUNT(*) FROM protocol_entries').fetchone()[0]} protocol entries")


if __name__ == "__main__":
    seed()
    print("✓ Seeded")
