"""Export a session as a standards-compliant .pcap file.

Wireshark can open the result directly. Useful when you want to leverage Wireshark's
extensive protocol dissectors (RSSI tracking, AVDTP, SDP, deep-packet inspection,
etc.) on top of what bt-spy already does. Linktype is picked based on the session's
capture_source.
"""

from __future__ import annotations

import sqlite3
import struct
from typing import BinaryIO

from . import db
from .capture.parser import LINKTYPE_BLUETOOTH_HCI_H4, LINKTYPE_BLUETOOTH_LE_LL

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4


def linktype_for_session(conn: sqlite3.Connection, session_id: int) -> int:
    row = conn.execute(
        "SELECT capture_source FROM sessions WHERE id=?", (session_id,)
    ).fetchone()
    src = row["capture_source"] if row else "nrf_sniffer"
    if src in ("packetlogger", "pklg_tail", "ble_host_probe"):
        return LINKTYPE_BLUETOOTH_HCI_H4
    return LINKTYPE_BLUETOOTH_LE_LL


def write_pcap(conn: sqlite3.Connection, session_id: int, out: BinaryIO) -> int:
    """Write all packets of a session to `out` in pcap (classic) format.

    Returns the number of packets written. Uses linktype based on capture_source,
    falling back to BLE_LL for unknown sources.
    """
    linktype = linktype_for_session(conn, session_id)
    snaplen = 65535
    # Global header (24 bytes)
    out.write(struct.pack(
        ">IHHiIII",
        PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
        0, 0, snaplen, linktype,
    ))
    # Get session start time so we can convert relative ts → absolute seconds.
    sess = conn.execute("SELECT started_at FROM sessions WHERE id=?", (session_id,)).fetchone()
    t0 = sess["started_at"] if sess else 0.0

    n = 0
    for r in conn.execute(
        "SELECT ts, raw FROM packets WHERE session_id=? ORDER BY ts ASC",
        (session_id,),
    ):
        raw = bytes(r["raw"])
        abs_ts = t0 + (r["ts"] or 0.0)
        sec = int(abs_ts)
        usec = int((abs_ts - sec) * 1_000_000)
        # Per-packet header (16 bytes): ts_sec ts_usec incl_len orig_len
        out.write(struct.pack(">IIII", sec, usec, len(raw), len(raw)))
        out.write(raw)
        n += 1
    return n


def export_session_to_path(session_id: int, path: str) -> int:
    conn = db.init_db()
    with open(path, "wb") as f:
        return write_pcap(conn, session_id, f)
