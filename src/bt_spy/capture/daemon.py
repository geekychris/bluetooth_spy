"""Capture daemon — turns BLE/HCI frames from any source into DB rows + a live broadcast queue.

Two capture sources today:
  - `nrf_sniffer` — over-the-air via the nRF52840 dongle (via Nordic's extcap).
  - `packetlogger` — host-side HCI via Apple's PacketLogger CLI.

To add a source, write a function that yields `parser.Frame` objects and pass it
to `CaptureDaemon(source=...)`. The daemon doesn't care where frames come from.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue
from typing import Callable, Iterator

from .. import db
from ..config import settings
from . import extcap, packetlogger, parser

log = logging.getLogger(__name__)


@dataclass
class CaptureStatus:
    session_id: int | None
    label: str
    started_at: float
    packet_count: int            # packets actually stored (and broadcast)
    last_packet_at: float | None
    error: str | None = None
    packets_seen: int = 0        # total decoded frames (pre-filter)
    packets_dropped_by_filter: int = 0
    device_filter: list[str] | None = None


class CaptureDaemon:
    """Runs a frame source and writes parsed frames into SQLite.

    Subscribers (the WebSocket layer, the MCP server) can register a callback
    via `add_subscriber(fn)` to receive every decoded packet as a dict.

    `source` is one of: 'nrf_sniffer' (default) or 'packetlogger'.
    """

    def __init__(
        self,
        *,
        label: str,
        notes: str | None = None,
        device_mac: str | None = None,
        device_name: str | None = None,
        source: str = "nrf_sniffer",
        source_args: dict | None = None,
        device_filter: list[str] | None = None,
    ) -> None:
        self.label = label
        self.notes = notes
        self.device_mac = device_mac
        self.device_name = device_name
        self.source = source
        self.source_args = source_args or {}
        # Capture-time allow-list of BD_ADDRs/UUIDs. When set, packets whose
        # device_addr (after conn_handle backfill) isn't in this set are dropped
        # — they never reach the DB or the WS broadcast. None = no filter.
        self.device_filter: set[str] | None = (
            {a.upper() for a in device_filter} if device_filter else None
        )

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._subscribers: list[Callable[[dict], None]] = []
        self._cleanup: Callable[[], None] | None = None
        # conn_handle (int) → device_addr (str). Populated from LE Connection Complete
        # events; used to backfill device_addr on subsequent ACL packets that don't
        # carry the BD_ADDR inline.
        self._conn_to_addr: dict[int, str] = {}
        # In-process cache of the device_aliases table; refreshed lazily during run.
        self._alias_cache: dict[str, str] = {}
        # Audit log of recently-learned (timestamp, conn_handle, device_addr) tuples,
        # capped at ~200 entries. Lets external code (e.g., the probe handler) ask
        # "which BD_ADDRs got connected between time T and now?" for UUID/MAC bridging.
        self._recent_addr_learnings: list[tuple[float, int, str]] = []
        self._status = CaptureStatus(
            session_id=None, label=label, started_at=time.time(), packet_count=0,
            last_packet_at=None,
            device_filter=sorted(self.device_filter) if self.device_filter else None,
        )

    # ---------- public ----------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Capture already running")
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="bt-spy-capture", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the capture. Terminates the source subprocess immediately so a
        read-blocked daemon thread can unblock and exit cleanly."""
        self._stop.set()
        # Kill the source's underlying subprocess (if any) so the blocked read returns.
        if self._cleanup:
            try:
                self._cleanup()
            except Exception as exc:
                log.warning("stop: cleanup failed: %s", exc)
        if self._thread:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                log.warning("capture thread did not exit within %.1fs", timeout)

    def add_subscriber(self, fn: Callable[[dict], None]) -> None:
        self._subscribers.append(fn)

    def remove_subscriber(self, fn: Callable[[dict], None]) -> None:
        if fn in self._subscribers:
            self._subscribers.remove(fn)

    @property
    def status(self) -> CaptureStatus:
        return self._status

    def recent_address_learnings(self, since: float) -> list[dict]:
        """Return (ts, conn_handle, device_addr) tuples learned at or after `since`.

        Used by the probe API to bridge bleak's CoreBluetooth UUID to the real MAC
        the daemon observed during the connection.
        """
        return [
            {"ts": t, "conn_handle": ch, "device_addr": mac}
            for (t, ch, mac) in self._recent_addr_learnings
            if t >= since
        ]

    # ---------- internals ----------

    def _start_source(self) -> Iterator[parser.Frame]:
        """Resolve the configured source and return a Frame iterator.

        Also stashes a cleanup callable on self._cleanup so _run can terminate
        any subprocess we launched even if the iterator is mid-yield when stop fires.
        """
        if self.source == "nrf_sniffer":
            # Prefer the new nrfutil 8.x binary; fall back to the legacy Python script.
            nrfutil_bin = extcap.find_nrfutil_binary()
            if nrfutil_bin is not None:
                # Translate device_filter (if it has exactly one entry) into a
                # sniffer-side --follow filter — much more efficient than dropping
                # in software, because the dongle stops following channels for
                # non-target devices.
                follow_addr = None
                if self.device_filter and len(self.device_filter) == 1:
                    only = next(iter(self.device_filter))
                    # nrfutil expects MAC like AA:BB:CC:DD:EE:FF (not CB UUID)
                    if ":" in only and len(only) == 17:
                        follow_addr = only
                sniff = extcap.start_nrfutil_sniff(
                    binary=nrfutil_bin,
                    follow_address=follow_addr,
                )
                log.info("nrfutil ble-sniffer launched: port=%s pcap=%s",
                         sniff.port, sniff.pcap_path)
                self._cleanup = lambda: (
                    sniff.process.terminate(),
                    sniff.pcap_path.unlink(missing_ok=True),
                )
                return parser.iter_pcap_classic_tail(sniff.pcap_path, stop_event=self._stop)
            # Legacy fallback for older Nordic installs
            session = extcap.start_extcap()
            log.info("legacy extcap launched: script=%s port=%s", session.script, session.port)
            self._cleanup = lambda: session.process.terminate()
            assert session.process.stdout is not None
            return parser.iter_pcapng_frames(session.process.stdout)
        if self.source == "packetlogger":
            live = packetlogger.start_live()
            log.info("PacketLogger CLI launched: %s", live.binary)
            self._cleanup = lambda: live.process.terminate()
            return packetlogger.iter_live_frames(live)
        if self.source == "pklg_tail":
            path = self.source_args.get("path")
            if not path:
                raise ValueError("pklg_tail source requires source_args={'path': '...'}")
            log.info("Tailing PL.app live file: %s", path)
            # No subprocess to clean up — the generator respects self._stop via stop_event.
            return packetlogger.iter_pklg_tail(path, stop_event=self._stop)
        raise ValueError(f"Unknown capture source: {self.source!r}")

    def _run(self) -> None:
        settings.ensure_dirs()
        conn = db.init_db()
        sid = db.start_session(
            conn,
            self.label,
            notes=self.notes,
            device_mac=self.device_mac,
            device_name=self.device_name,
            capture_source=self.source,
        )
        self._status.session_id = sid
        self._status.started_at = time.time()
        # Seed the alias cache so live events get names from the start.
        self._alias_cache = db.get_device_aliases(conn)
        log.info("Capture session %s started (label=%s, source=%s, aliases=%d)",
                 sid, self.label, self.source, len(self._alias_cache))

        try:
            frames = self._start_source()
        except Exception as exc:
            self._status.error = str(exc)
            log.error("Failed to start source %s: %s", self.source, exc)
            db.end_session(conn, sid)
            return

        try:
            t0 = time.monotonic()
            for frame in frames:
                if self._stop.is_set():
                    break
                decoded = parser.decode_frame(frame)
                rel_ts = time.monotonic() - t0

                # Learn conn_handle → BD_ADDR from connection-setup events.
                if decoded.conn_handle is not None and decoded.device_addr:
                    if self._conn_to_addr.get(decoded.conn_handle) != decoded.device_addr:
                        # First time seeing this (conn, addr) pair — record for bridging.
                        self._recent_addr_learnings.append(
                            (time.time(), decoded.conn_handle, decoded.device_addr)
                        )
                        if len(self._recent_addr_learnings) > 200:
                            self._recent_addr_learnings = self._recent_addr_learnings[-100:]
                    self._conn_to_addr[decoded.conn_handle] = decoded.device_addr
                # Backfill device_addr for ACL packets that carry only the conn_handle.
                if decoded.device_addr is None and decoded.conn_handle is not None:
                    decoded.device_addr = self._conn_to_addr.get(decoded.conn_handle)
                # If adv data carried a Complete/Shortened Local Name, persist it.
                if decoded.device_addr and decoded.device_name:
                    try:
                        db.upsert_device_alias(conn, decoded.device_addr, decoded.device_name, source="adv")
                    except Exception:
                        pass

                # Track every decoded frame whether or not we end up storing it
                # — lets the UI distinguish "no traffic" from "filter dropped everything".
                self._status.packets_seen += 1

                # Capture-time filter: drop packets that aren't for one of the
                # devices the user asked to capture. We've already updated the
                # conn_handle→addr mapping above, so subsequent ACL packets on
                # that conn handle will be classified correctly.
                if self.device_filter is not None:
                    addr = (decoded.device_addr or "").upper()
                    if addr not in self.device_filter:
                        self._status.packets_dropped_by_filter += 1
                        continue

                pid = db.insert_packet(
                    conn,
                    sid,
                    ts=rel_ts,
                    direction=decoded.direction,
                    pdu_type=decoded.pdu_type,
                    handle=decoded.handle,
                    conn_handle=decoded.conn_handle,
                    device_addr=decoded.device_addr,
                    opcode=decoded.opcode,
                    payload=decoded.payload,
                    raw=frame.raw,
                    decoded=decoded.summary,
                )
                self._status.packet_count += 1
                self._status.last_packet_at = time.time()
                # Look up a friendly name (from any source) to attach to the event,
                # so the UI live feed can render it without an extra round-trip.
                friendly = None
                if decoded.device_addr:
                    if decoded.device_name:
                        friendly = decoded.device_name
                    else:
                        # cheap lookup against the in-process aliases cache, refreshed lazily.
                        friendly = self._alias_cache.get(decoded.device_addr)
                        if friendly is None and (self._status.packet_count % 50 == 0):
                            self._alias_cache = db.get_device_aliases(conn)
                            friendly = self._alias_cache.get(decoded.device_addr)
                event = {
                    "session_id": sid,
                    "packet_id": pid,
                    "ts": rel_ts,
                    "direction": decoded.direction,
                    "pdu_type": decoded.pdu_type,
                    "handle": decoded.handle,
                    "conn_handle": decoded.conn_handle,
                    "device_addr": decoded.device_addr,
                    "device_name": friendly,
                    "opcode": decoded.opcode,
                    "payload_hex": decoded.payload.hex() if decoded.payload else None,
                    "raw_hex": frame.raw.hex(),
                    "layers": decoded.summary.get("layers"),
                }
                for sub in list(self._subscribers):
                    try:
                        sub(event)
                    except Exception as e:
                        log.warning("Subscriber failed: %s", e)
        except Exception as exc:
            self._status.error = str(exc)
            log.exception("Capture loop crashed")
        finally:
            if self._cleanup:
                try:
                    self._cleanup()
                except Exception:
                    pass
            db.end_session(conn, sid)
            log.info("Capture session %s ended (packets=%d)", sid, self._status.packet_count)


def run_blocking(label: str, *, notes: str | None = None, source: str = "nrf_sniffer") -> CaptureStatus:
    """Run a capture until Ctrl-C. Used by the CLI's `capture` command."""
    d = CaptureDaemon(label=label, notes=notes, source=source)
    d.start()
    try:
        while not d._stop.is_set() and (d._thread and d._thread.is_alive()):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        d.stop()
    return d.status


def import_pklg(
    path: str | Path,
    label: str,
    *,
    notes: str | None = None,
    device_name: str | None = None,
) -> dict:
    """Offline ingest of a saved Apple PacketLogger .pklg file.

    Creates a session, parses every record, writes packets to the DB. Returns
    a summary dict with session_id + packet_count.
    """
    settings.ensure_dirs()
    conn = db.init_db()
    sid = db.start_session(
        conn, label, notes=notes, device_name=device_name, capture_source="packetlogger",
    )
    t0_ts: float | None = None
    count = 0
    for frame in packetlogger.iter_pklg_file(path):
        if t0_ts is None:
            t0_ts = frame.timestamp
        rel_ts = frame.timestamp - (t0_ts or 0.0)
        decoded = parser.decode_frame(frame)
        db.insert_packet(
            conn, sid,
            ts=rel_ts,
            direction=decoded.direction or frame.decoded.get("direction_hint"),
            pdu_type=decoded.pdu_type,
            handle=decoded.handle,
            conn_handle=decoded.conn_handle,
            device_addr=decoded.device_addr,
            opcode=decoded.opcode,
            payload=decoded.payload,
            raw=frame.raw,
            decoded={**frame.decoded, **decoded.summary},
        )
        count += 1
    db.end_session(conn, sid)
    return {"session_id": sid, "packet_count": count, "source_file": str(path)}
