"""Apple PacketLogger (.pklg) parser + live capture wrapper.

PacketLogger is Apple's built-in HCI logger. It captures every Bluetooth packet
the Mac's own controller handles — including BLE connections you initiated from
this Mac (e.g., from bleak). For traffic between *other* devices (your phone and
a BLE peripheral), you still need the over-the-air sniffer.

This module handles two ingest paths:

  - `iter_pklg_file(path)` — yields Frame objects from a saved .pklg file.
  - `start_live(progress_cb)` — spawns the PacketLogger CLI binary (bundled in
    PacketLogger.app) and streams pcap-style frames. The CLI isn't always
    present; we fall back to a clear error message telling the user to capture
    via the GUI and then `bt-spy import-pklg`.

.pklg record layout (all big-endian):

    +-------------------+
    |  length    (u32)  |   size of (ts_sec + ts_usec + type + payload) — i.e., excludes the length field itself
    |  ts_sec    (u32)  |
    |  ts_usec   (u32)  |
    |  type      (u8)   |   PacketLogger packet-type code (see TYPE_TO_H4)
    |  payload   ...    |   length - 9 bytes
    +-------------------+

So total record on disk = 4 + length bytes. This matches Apple's PacketLogger.app
output verified against tshark's pklg dissector.

Type codes correspond to HCI H4 indicator bytes per Bluetooth Core spec, with
direction flags Apple adds (send vs recv ACL etc.). We translate to a standard
H4 frame (indicator byte + HCI payload) so the existing scapy-based decoder
can handle them.
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from .parser import Frame, LINKTYPE_BLUETOOTH_HCI_H4

log = logging.getLogger(__name__)

# PacketLogger type → HCI H4 indicator + direction tag we expose on the Frame.
# H4 indicators: 0x01=CMD, 0x02=ACL, 0x03=SCO, 0x04=EVT.
TYPE_TO_H4: dict[int, tuple[int, str]] = {
    0x00: (0x01, "host->controller"),   # HCI Command
    0x01: (0x04, "controller->host"),   # HCI Event
    0x02: (0x02, "host->controller"),   # ACL Send
    0x03: (0x02, "controller->host"),   # ACL Recv
    0x08: (0x03, "host->controller"),   # SCO Send
    0x09: (0x03, "controller->host"),   # SCO Recv
    0xFB: (0x04, "controller->host"),   # LE Meta (uncommon)
}

# Common locations for Apple's PacketLogger CLI binary (ships inside the .app).
PACKETLOGGER_CLI_CANDIDATES = [
    Path("/Applications/PacketLogger.app/Contents/MacOS/PacketLogger"),
    Path("/Applications/Utilities/PacketLogger.app/Contents/MacOS/PacketLogger"),
]


@dataclass
class PklgRecord:
    ts: float
    type_code: int
    payload: bytes  # raw HCI bytes (no H4 indicator)


def iter_pklg_records(stream: BinaryIO) -> Iterator[PklgRecord]:
    """Yield PklgRecord objects from a .pklg byte stream. Stops cleanly on EOF.

    Tolerant of truncated trailing records (last record short by < 13 bytes is
    silently dropped) so partial files / mid-write reads don't crash the importer.
    """
    while True:
        header = stream.read(13)
        if len(header) < 13:
            return
        length, ts_sec, ts_usec, type_code = struct.unpack(">IIIB", header)
        # `length` covers ts + type + payload (9 bytes of header-after-length + payload).
        body_len = length - 9
        if body_len < 0:
            log.warning("pklg record with negative body_len (length=%d) — skipping", length)
            return
        payload = stream.read(body_len)
        if len(payload) < body_len:
            log.warning("Truncated .pklg record at EOF")
            return
        yield PklgRecord(
            ts=ts_sec + ts_usec / 1_000_000.0,
            type_code=type_code,
            payload=payload,
        )


def pklg_record_to_frame(rec: PklgRecord) -> Frame | None:
    """Convert a PklgRecord to a Frame suitable for our existing decoder.

    Returns None for records we don't have an H4 mapping for (rare; e.g.,
    PacketLogger-internal markers).
    """
    mapping = TYPE_TO_H4.get(rec.type_code)
    if mapping is None:
        return None
    h4_indicator, direction = mapping
    raw = bytes([h4_indicator]) + rec.payload
    return Frame(
        timestamp=rec.ts,
        linktype=LINKTYPE_BLUETOOTH_HCI_H4,
        raw=raw,
        decoded={"packetlogger_type": rec.type_code, "direction_hint": direction},
    )


def iter_pklg_file(path: str | Path) -> Iterator[Frame]:
    """Yield Frame objects from a saved .pklg file."""
    with open(path, "rb") as f:
        for rec in iter_pklg_records(f):
            frame = pklg_record_to_frame(rec)
            if frame is not None:
                yield frame


def iter_pklg_tail(
    path: str | Path,
    *,
    stop_event: "threading.Event | None" = None,
    poll_interval_s: float = 0.05,
    initial_wait_s: float = 3.0,
) -> Iterator[Frame]:
    """Tail a .pklg file that PacketLogger.app is incrementally writing to.

    Use case: in PL.app, hit record, then *File → Save Live Capture As…* and
    point at a path. PL writes each new record to the file as it arrives. This
    function opens the file and yields Frames as records appear, sleeping
    briefly when there's nothing new. Stops when `stop_event` is set.

    The file may not exist yet when capture starts (PL creates it on first
    write). We poll for up to `initial_wait_s` for it to appear.
    """
    deadline = time.monotonic() + initial_wait_s
    p = Path(path)
    while not p.exists():
        if stop_event and stop_event.is_set():
            return
        if time.monotonic() > deadline:
            raise FileNotFoundError(
                f"Live PL file {p} didn't appear within {initial_wait_s}s. "
                "Make sure PL.app is recording AND you used File→Save Live Capture As to this path."
            )
        time.sleep(0.1)

    with open(p, "rb") as f:
        buf = b""
        while True:
            if stop_event and stop_event.is_set():
                return
            # Try to assemble one record. Need 13-byte header then payload.
            while len(buf) < 13:
                more = f.read(8192)
                if more:
                    buf += more
                    continue
                if stop_event and stop_event.is_set():
                    return
                time.sleep(poll_interval_s)
            length = int.from_bytes(buf[:4], "big")
            # `length` covers ts(8) + type(1) + payload — i.e., excludes the 4-byte length field.
            total_record_size = 4 + length
            if length < 9 or length > 1_000_000:
                # Corrupt / wrong file format — bail loudly so the user knows.
                raise ValueError(
                    f"PL-tail: implausible record length {length} at offset {f.tell()-len(buf)}. "
                    "Is the target path actually a .pklg file being written by PL.app?"
                )
            while len(buf) < total_record_size:
                more = f.read(8192)
                if more:
                    buf += more
                    continue
                if stop_event and stop_event.is_set():
                    return
                time.sleep(poll_interval_s)
            record_bytes = buf[:total_record_size]
            buf = buf[total_record_size:]
            ts_sec = int.from_bytes(record_bytes[4:8], "big")
            ts_usec = int.from_bytes(record_bytes[8:12], "big")
            type_code = record_bytes[12]
            payload = record_bytes[13:]
            rec = PklgRecord(
                ts=ts_sec + ts_usec / 1_000_000.0,
                type_code=type_code,
                payload=payload,
            )
            frame = pklg_record_to_frame(rec)
            if frame is not None:
                yield frame




# ----- Live capture --------------------------------------------------------

def find_live_pklg_file() -> Path | None:
    """Detect the .pklg file PacketLogger.app is currently writing to.

    PL.app opens the file when the user picks File → Save Live Capture As…;
    we discover it via lsof so the UI can pre-fill the pklg_tail path field.

    We use `lsof -F nfa` (machine-readable, one field per line) so paths with
    Unicode whitespace (macOS's "Save Live Capture As…" uses U+202F NARROW
    NO-BREAK SPACE in default filenames) round-trip correctly.
    """
    try:
        pl_pids = subprocess.check_output(
            ["pgrep", "-f", "/Applications/PacketLogger.app/Contents/MacOS/PacketLogger"],
            text=True,
        ).split()
    except subprocess.CalledProcessError:
        return None
    for pid in pl_pids:
        try:
            out = subprocess.check_output(
                ["lsof", "-p", pid, "-F", "nfa"],
                text=True, stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            continue
        # -F output: each line starts with a field-type char. We care about
        # 'a' (access mode: r/w/u) and 'n' (name). Within a single fd block,
        # access comes before name.
        cur_access = ""
        for line in out.splitlines():
            if not line:
                continue
            tag, val = line[0], line[1:]
            if tag == "a":
                cur_access = val  # 'w', 'r', 'u' (read+write)
            elif tag == "n":
                if val.endswith(".pklg") and ("w" in cur_access or "u" in cur_access):
                    p = Path(val)
                    if p.exists():
                        return p
                cur_access = ""
            elif tag == "f":  # new fd block starts
                cur_access = ""
    return None


def find_packetlogger_cli() -> Path | None:
    """Find Apple's PacketLogger binary if installed."""
    for p in PACKETLOGGER_CLI_CANDIDATES:
        if p.exists() and os.access(p, os.X_OK):
            return p
    found = shutil.which("PacketLogger")
    return Path(found) if found else None


def have_packetlogger_app() -> bool:
    """True if PacketLogger.app is installed (CLI or GUI usable)."""
    return any(Path(p).parent.parent.parent.exists() for p in PACKETLOGGER_CLI_CANDIDATES) \
        or find_packetlogger_cli() is not None


@dataclass
class LiveSession:
    process: subprocess.Popen
    binary: Path


def start_live() -> LiveSession:
    """Spawn the PacketLogger CLI in streaming mode.

    Note: Apple's PacketLogger CLI flags vary across macOS releases. We use the
    most-broadly-supported invocation (`-f stdout` for .pklg-on-stdout). If it
    doesn't behave, the cleanest fallback is to run PacketLogger.app, save a
    file, and `bt-spy import-pklg`.
    """
    cli = find_packetlogger_cli()
    if cli is None:
        raise FileNotFoundError(
            "PacketLogger CLI not found. Install 'Additional Tools for Xcode' from "
            "https://developer.apple.com/download/all/ (search 'Additional Tools'), "
            "or capture via PacketLogger.app's GUI and use `bt-spy import-pklg FILE`."
        )
    cmd = [str(cli), "-f", "stdout"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    return LiveSession(process=proc, binary=cli)


def iter_live_frames(session: LiveSession) -> Iterator[Frame]:
    """Stream Frame objects from a running live session."""
    assert session.process.stdout is not None
    for rec in iter_pklg_records(session.process.stdout):
        frame = pklg_record_to_frame(rec)
        if frame is not None:
            yield frame
