"""SQLite storage for sessions, packets, annotations, protocol entries, replays.

Schema is intentionally narrow and append-mostly. Packets are the ground truth;
everything else (annotations, protocol_entries, replays) is interpretation that can
be regenerated. Open one DB connection per process; SQLite serializes writes for us.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    label           TEXT NOT NULL,
    notes           TEXT,
    device_mac      TEXT,
    device_name     TEXT,
    started_at      REAL NOT NULL,
    ended_at        REAL,
    capture_source  TEXT NOT NULL DEFAULT 'nrf_sniffer'
);

CREATE TABLE IF NOT EXISTS packets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,           -- monotonic seconds since session start
    direction       TEXT,                    -- 'central->peripheral' / 'peripheral->central' / 'adv'
    pdu_type        TEXT,                    -- ATT_WRITE_REQ, ATT_HANDLE_VALUE_NTF, ADV_IND, ...
    handle          INTEGER,                 -- ATT handle (if applicable)
    conn_handle     INTEGER,                 -- BLE link-layer connection handle (HCI ACL); proxy for "device"
    device_addr     TEXT,                    -- BD_ADDR 'AA:BB:CC:DD:EE:FF' — the real device identity
    opcode          INTEGER,                 -- ATT opcode (if applicable)
    payload         BLOB,                    -- raw value bytes (the part you usually care about)
    raw             BLOB NOT NULL,           -- complete frame
    decoded         TEXT                     -- JSON: scapy summary + any extracted fields
);
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_packets_handle  ON packets(session_id, handle);
-- idx_packets_conn is created in _migrate after ensuring the column exists.

CREATE TABLE IF NOT EXISTS annotations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    packet_id_start INTEGER NOT NULL,
    packet_id_end   INTEGER NOT NULL,
    label           TEXT NOT NULL,
    notes           TEXT,
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name     TEXT,
    handle          INTEGER NOT NULL,
    char_uuid       TEXT,                    -- characteristic UUID; needed for HA / driver export
    service_uuid    TEXT,                    -- enclosing service UUID; used for HA bluetooth matchers
    direction       TEXT NOT NULL,
    name            TEXT NOT NULL,           -- canonical name from integrations.vocabulary
    structure_json  TEXT NOT NULL,           -- field layout: [{name,size,encoding}, ...]
    decoder_py      TEXT,                    -- optional Python snippet body: def decode(payload) -> dict
    encoder_py      TEXT,                    -- optional Python snippet body: def encode(**kwargs) -> bytes
    confidence      REAL NOT NULL DEFAULT 0.5,
    notes           TEXT,
    created_at      REAL NOT NULL,
    UNIQUE(device_name, handle, direction, name)
);

CREATE TABLE IF NOT EXISTS replays (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    target_mac      TEXT NOT NULL,
    sent_json       TEXT NOT NULL,           -- list of {handle, payload_hex, mutation?}
    response_json   TEXT,                    -- list of {handle, payload_hex, ts}
    status          TEXT NOT NULL,           -- 'ok' / 'error' / 'timeout'
    error           TEXT,
    started_at      REAL NOT NULL,
    ended_at        REAL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Device name lookup. Populated from:
--   1. Advertising data we parse (Complete Local Name AD records)
--   2. bleak Scan results (CoreBluetooth's resolved names)
--   3. bleak Probe results (Device Name 0x2A00 GATT reads)
-- Address resolution: BLE addresses rotate for privacy devices, so a given name
-- may be valid only for the lifetime of an address. Last_seen helps spot stale rows.
CREATE TABLE IF NOT EXISTS device_aliases (
    device_addr  TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    source       TEXT,        -- 'adv' / 'scan' / 'probe' / 'user'
    last_seen    REAL NOT NULL
);

-- Long-Term Keys for paired devices. With a peer's LTK, encrypted ATT traffic in
-- a captured connection can be decrypted post-hoc (since LE Secure Connections /
-- legacy pairing use AES-CCM keyed off LTK + nonce derived from SKD/IV exchanged
-- in plaintext during the connection-encrypt-request handshake).
CREATE TABLE IF NOT EXISTS device_ltks (
    device_addr  TEXT PRIMARY KEY,
    ltk_hex      TEXT NOT NULL,        -- 16 bytes hex; the long-term key
    rand_hex     TEXT,                 -- 8 bytes hex; some pairing flows need it
    ediv         INTEGER,
    notes        TEXT,
    created_at   REAL NOT NULL
);
"""


def get_conn(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: Path | None = None) -> sqlite3.Connection:
    conn = get_conn(db_path)
    conn.executescript(SCHEMA)
    # Lightweight migrations: idempotent ALTERs for older DBs.
    _migrate(conn)
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '2')"
    )
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(packets)")}
    if "conn_handle" not in cols:
        conn.execute("ALTER TABLE packets ADD COLUMN conn_handle INTEGER")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_conn ON packets(session_id, conn_handle)")
    if "device_addr" not in cols:
        conn.execute("ALTER TABLE packets ADD COLUMN device_addr TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_addr ON packets(session_id, device_addr)")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(protocol_entries)")}
    if "char_uuid" not in cols:
        conn.execute("ALTER TABLE protocol_entries ADD COLUMN char_uuid TEXT")
    if "service_uuid" not in cols:
        conn.execute("ALTER TABLE protocol_entries ADD COLUMN service_uuid TEXT")


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


# ---------- typed helpers ----------


@dataclass
class Session:
    id: int
    label: str
    notes: str | None
    device_mac: str | None
    device_name: str | None
    started_at: float
    ended_at: float | None
    capture_source: str


def start_session(
    conn: sqlite3.Connection,
    label: str,
    *,
    notes: str | None = None,
    device_mac: str | None = None,
    device_name: str | None = None,
    capture_source: str = "nrf_sniffer",
) -> int:
    cur = conn.execute(
        "INSERT INTO sessions(label, notes, device_mac, device_name, started_at, capture_source) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (label, notes, device_mac, device_name, time.time(), capture_source),
    )
    return cur.lastrowid


def end_session(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute("UPDATE sessions SET ended_at=? WHERE id=?", (time.time(), session_id))


def insert_packet(
    conn: sqlite3.Connection,
    session_id: int,
    *,
    ts: float,
    direction: str | None,
    pdu_type: str | None,
    handle: int | None,
    opcode: int | None,
    payload: bytes | None,
    raw: bytes,
    decoded: dict[str, Any] | None,
    conn_handle: int | None = None,
    device_addr: str | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO packets(session_id, ts, direction, pdu_type, handle, conn_handle, device_addr, "
        "opcode, payload, raw, decoded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            session_id,
            ts,
            direction,
            pdu_type,
            handle,
            conn_handle,
            device_addr,
            opcode,
            payload,
            raw,
            json.dumps(decoded) if decoded is not None else None,
        ),
    )
    return cur.lastrowid


def list_sessions(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM sessions ORDER BY started_at DESC")]


def get_packets(
    conn: sqlite3.Connection,
    session_id: int,
    *,
    handle: int | None = None,
    direction: str | None = None,
    pdu_type: str | None = None,
    conn_handle: int | None = None,
    device_addr: str | list[str] | None = None,
    limit: int | None = None,
) -> list[dict]:
    """`device_addr` accepts a single string or a list — list filters via IN."""
    sql = "SELECT * FROM packets WHERE session_id=?"
    args: list[Any] = [session_id]
    if handle is not None:
        sql += " AND handle=?"
        args.append(handle)
    if direction is not None:
        sql += " AND direction=?"
        args.append(direction)
    if pdu_type is not None:
        sql += " AND pdu_type=?"
        args.append(pdu_type)
    if conn_handle is not None:
        sql += " AND conn_handle=?"
        args.append(conn_handle)
    if device_addr is not None:
        if isinstance(device_addr, str):
            sql += " AND device_addr=?"
            args.append(device_addr)
        else:
            addrs = list(device_addr)
            if addrs:
                placeholders = ",".join("?" * len(addrs))
                sql += f" AND device_addr IN ({placeholders})"
                args.extend(addrs)
    sql += " ORDER BY ts ASC"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    return [dict(r) for r in conn.execute(sql, args)]


def addrs_for_alias_name(conn: sqlite3.Connection, name: str) -> list[str]:
    """All BD_ADDRs/UUIDs that have been aliased with the given name."""
    return [r["device_addr"] for r in conn.execute(
        "SELECT device_addr FROM device_aliases WHERE name=?", (name,)
    )]


def devices_in_session(conn: sqlite3.Connection, session_id: int) -> list[dict]:
    """Distinct BD_ADDRs in this session, with packet counts and resolved name (if any)."""
    return [dict(r) for r in conn.execute(
        """
        SELECT p.device_addr AS device_addr,
               COUNT(*) AS n,
               COALESCE(a.name, '') AS name,
               a.source AS name_source
        FROM packets p
        LEFT JOIN device_aliases a ON a.device_addr = p.device_addr
        WHERE p.session_id=? AND p.device_addr IS NOT NULL
        GROUP BY p.device_addr
        ORDER BY n DESC
        """,
        (session_id,),
    )]


def upsert_ltk(
    conn: sqlite3.Connection,
    device_addr: str,
    ltk_hex: str,
    *,
    rand_hex: str | None = None,
    ediv: int | None = None,
    notes: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO device_ltks(device_addr, ltk_hex, rand_hex, ediv, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_addr) DO UPDATE SET
            ltk_hex=excluded.ltk_hex, rand_hex=excluded.rand_hex,
            ediv=excluded.ediv, notes=excluded.notes
        """,
        (device_addr, ltk_hex, rand_hex, ediv, notes, time.time()),
    )


def get_ltks(conn: sqlite3.Connection) -> dict[str, dict]:
    return {r["device_addr"]: dict(r) for r in conn.execute("SELECT * FROM device_ltks")}


def upsert_device_alias(
    conn: sqlite3.Connection,
    device_addr: str,
    name: str,
    source: str = "adv",
) -> None:
    """Insert/update an addr→name alias. Newer source overrides older ones with the
    same precedence as the input — we always replace because device names can
    actually change (e.g. user renames their iPhone)."""
    conn.execute(
        """
        INSERT INTO device_aliases(device_addr, name, source, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(device_addr) DO UPDATE SET
            name=excluded.name, source=excluded.source, last_seen=excluded.last_seen
        """,
        (device_addr, name, source, time.time()),
    )


def get_device_aliases(conn: sqlite3.Connection) -> dict[str, str]:
    return {r["device_addr"]: r["name"] for r in conn.execute(
        "SELECT device_addr, name FROM device_aliases"
    )}


def get_packet(conn: sqlite3.Connection, packet_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM packets WHERE id=?", (packet_id,)).fetchone()
    return dict(row) if row else None


def get_annotations(conn: sqlite3.Connection, session_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM annotations WHERE session_id=? ORDER BY packet_id_start ASC",
        (session_id,),
    )]


def latest_packet_id(conn: sqlite3.Connection, session_id: int) -> int | None:
    row = conn.execute(
        "SELECT MAX(id) AS m FROM packets WHERE session_id=?", (session_id,)
    ).fetchone()
    return row["m"]


def conn_handles_in_session(conn: sqlite3.Connection, session_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT conn_handle, COUNT(*) AS n FROM packets WHERE session_id=? AND conn_handle IS NOT NULL "
        "GROUP BY conn_handle ORDER BY n DESC", (session_id,),
    )]


def add_annotation(
    conn: sqlite3.Connection,
    session_id: int,
    packet_id_start: int,
    packet_id_end: int,
    label: str,
    notes: str | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO annotations(session_id, packet_id_start, packet_id_end, label, notes, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, packet_id_start, packet_id_end, label, notes, time.time()),
    )
    return cur.lastrowid


def upsert_protocol_entry(
    conn: sqlite3.Connection,
    *,
    device_name: str | None,
    handle: int,
    direction: str,
    name: str,
    structure: list[dict],
    char_uuid: str | None = None,
    service_uuid: str | None = None,
    decoder_py: str | None = None,
    encoder_py: str | None = None,
    confidence: float = 0.5,
    notes: str | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO protocol_entries(device_name, handle, char_uuid, service_uuid, direction,
                                     name, structure_json, decoder_py, encoder_py,
                                     confidence, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_name, handle, direction, name) DO UPDATE SET
            char_uuid=excluded.char_uuid,
            service_uuid=excluded.service_uuid,
            structure_json=excluded.structure_json,
            decoder_py=excluded.decoder_py,
            encoder_py=excluded.encoder_py,
            confidence=excluded.confidence,
            notes=excluded.notes
        """,
        (
            device_name,
            handle,
            char_uuid,
            service_uuid,
            direction,
            name,
            json.dumps(structure),
            decoder_py,
            encoder_py,
            confidence,
            notes,
            time.time(),
        ),
    )
    return cur.lastrowid


def list_protocol_entries(
    conn: sqlite3.Connection, device_name: str | None = None
) -> list[dict]:
    if device_name:
        rows = conn.execute(
            "SELECT * FROM protocol_entries WHERE device_name=? ORDER BY handle, direction, name",
            (device_name,),
        )
    else:
        rows = conn.execute(
            "SELECT * FROM protocol_entries ORDER BY device_name, handle, direction, name"
        )
    return [dict(r) for r in rows]


def record_replay(
    conn: sqlite3.Connection,
    *,
    session_id: int | None,
    target_mac: str,
    sent: list[dict],
    response: list[dict] | None,
    status: str,
    error: str | None,
    started_at: float,
    ended_at: float | None,
) -> int:
    cur = conn.execute(
        "INSERT INTO replays(session_id, target_mac, sent_json, response_json, status, error, "
        "started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            session_id,
            target_mac,
            json.dumps(sent),
            json.dumps(response) if response else None,
            status,
            error,
            started_at,
            ended_at,
        ),
    )
    return cur.lastrowid


def diff_sessions(
    conn: sqlite3.Connection, baseline_id: int, candidate_id: int
) -> dict[str, Any]:
    """Return packets in `candidate` that have no matching (handle, payload) in `baseline`.

    "Matching" means same handle, direction, and payload bytes. This is the quickest
    way to surface what's new about an action you just performed.
    """

    def fingerprints(sid: int) -> set[tuple[int | None, str | None, bytes | None]]:
        rows = conn.execute(
            "SELECT handle, direction, payload FROM packets WHERE session_id=?", (sid,)
        )
        return {(r["handle"], r["direction"], bytes(r["payload"]) if r["payload"] else None) for r in rows}

    base = fingerprints(baseline_id)
    cand_rows = list(
        conn.execute(
            "SELECT * FROM packets WHERE session_id=? ORDER BY ts ASC", (candidate_id,)
        )
    )
    new_rows = []
    for r in cand_rows:
        key = (r["handle"], r["direction"], bytes(r["payload"]) if r["payload"] else None)
        if key not in base:
            new_rows.append(dict(r))
    return {
        "baseline_session_id": baseline_id,
        "candidate_session_id": candidate_id,
        "new_packet_count": len(new_rows),
        "new_packets": new_rows,
    }


def export_session_jsonl(conn: sqlite3.Connection, session_id: int) -> Iterable[str]:
    """Yield JSONL lines for a session — useful for handing to Claude in one chunk."""
    sess = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not sess:
        return
    yield json.dumps({"type": "session", **dict(sess)})
    for r in conn.execute(
        "SELECT * FROM packets WHERE session_id=? ORDER BY ts ASC", (session_id,)
    ):
        d = dict(r)
        if d["payload"] is not None:
            d["payload"] = bytes(d["payload"]).hex()
        d["raw"] = bytes(d["raw"]).hex()
        yield json.dumps({"type": "packet", **d})
