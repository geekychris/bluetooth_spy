"""Host BLE helpers — scan + probe.

These do double duty:

  1. They drive the Mac's BLE so you can capture in PacketLogger.app or via the
     nRF sniffer alongside, end-to-end.

  2. When you pass `record_as=LABEL` to probe(), each GATT read/notify/write is
     also written *directly* to the bt-spy DB as a capture session — no PacketLogger
     required. That's the path that gives you a working session immediately even
     when host-side sniffing isn't set up.

Recorded "packets" carry a synthetic raw blob (the H4-shaped ATT bytes) plus a
real direction/handle/payload. They behave like dongle/PacketLogger packets
everywhere downstream (diff, replay, integrations).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import db

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    address: str
    name: str | None
    rssi: int | None
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[int, str] = field(default_factory=dict)  # company_id → hex


async def scan(duration: float = 5.0) -> list[ScanResult]:
    """BLE-scan for `duration` seconds. Returns one entry per device seen.

    Also persists every (addr → name) the OS knows about into the global
    device_aliases table — so even devices that broadcast in privacy mode get
    a real name attached for the lifetime of their advertising address.
    """
    from bleak import BleakScanner

    devices_and_adv = await BleakScanner.discover(timeout=duration, return_adv=True)
    out: list[ScanResult] = []
    conn = db.init_db()
    for addr, (device, adv) in devices_and_adv.items():
        name = device.name or adv.local_name
        out.append(ScanResult(
            address=addr,
            name=name,
            rssi=getattr(adv, "rssi", None),
            service_uuids=list(adv.service_uuids or []),
            manufacturer_data={
                cid: data.hex() for cid, data in (adv.manufacturer_data or {}).items()
            },
        ))
        if name:
            db.upsert_device_alias(conn, addr, name, source="scan")
    out.sort(key=lambda r: -(r.rssi or -999))
    return out


@dataclass
class CharacteristicInfo:
    service_uuid: str
    char_uuid: str
    handle: int | None
    properties: list[str]
    read_value_hex: str | None = None
    read_error: str | None = None
    notify_received_hex: list[str] = field(default_factory=list)


@dataclass
class ProbeResult:
    address: str
    device_name: str | None
    characteristics: list[CharacteristicInfo] = field(default_factory=list)
    error: str | None = None
    session_id: int | None = None


async def probe(
    address: str,
    *,
    listen_for_notifications_ms: int = 2000,
    read_all_readable: bool = True,
    record_as: str | None = None,
    subscriber: Callable[[dict], None] | None = None,
) -> ProbeResult:
    """Connect to `address`, enumerate GATT, optionally read every readable
    characteristic, and subscribe to every notify-able one for the listen window.

    If `record_as` is given, a capture session with that label is created and
    every read / notify is written to the DB as a packet (with handle, payload,
    direction set), so the rest of bt-spy sees it as a normal session.

    `subscriber`, if given, is called with each packet event (same shape the
    WebSocket layer broadcasts) so the live UI feed updates as the probe runs.
    """
    from bleak import BleakClient

    result = ProbeResult(address=address, device_name=None)
    notifies: dict[str, list[str]] = {}

    # --- session recording (optional) ---
    session_id: int | None = None
    conn = None
    t0 = time.monotonic()
    if record_as:
        conn = db.init_db()
        session_id = db.start_session(
            conn, record_as, notes=f"ble_probe of {address}",
            device_name=None, capture_source="ble_host_probe",
        )
        log.info("Recording probe to session %s (label=%s)", session_id, record_as)

    def _emit(packet_id: int, direction: str, handle: int | None, payload: bytes,
              opcode: int, pdu_type: str) -> None:
        if subscriber is None:
            return
        try:
            subscriber({
                "session_id": session_id,
                "packet_id": packet_id,
                "ts": time.monotonic() - t0,
                "direction": direction,
                "pdu_type": pdu_type,
                "handle": handle,
                "opcode": opcode,
                "payload_hex": payload.hex(),
            })
        except Exception as exc:
            log.warning("subscriber raised: %s", exc)

    def _record_packet(direction: str, handle: int | None, payload: bytes,
                       opcode: int, pdu_type: str) -> None:
        if conn is None or session_id is None:
            return
        # Synthesize a minimal ATT-shaped raw blob so downstream parsers see a real frame.
        raw = bytes([opcode]) + (handle or 0).to_bytes(2, "little") + payload
        pid = db.insert_packet(
            conn, session_id,
            ts=time.monotonic() - t0,
            direction=direction, pdu_type=pdu_type,
            handle=handle, opcode=opcode, payload=payload, raw=raw,
            decoded={"source": "ble_probe", "synthetic": True},
        )
        _emit(pid, direction, handle, payload, opcode, pdu_type)

    def _cb_for(uuid: str, handle: int | None):
        notifies.setdefault(uuid, [])
        def cb(_sender, data):
            b = bytes(data)
            notifies[uuid].append(b.hex())
            _record_packet("peripheral->central", handle, b, 0x1B, "ATT_HANDLE_VALUE_NTF")
        return cb

    try:
        async with BleakClient(address, timeout=20.0) as client:
            # Try to learn the device's name for the alias DB. bleak exposes it
            # as client._device.name when set; some versions only via a GATT read.
            try:
                bleak_name = getattr(getattr(client, "_backend", None), "_device", None)
                friendly = getattr(bleak_name, "name", None)
                if friendly:
                    result.device_name = friendly
                    db.upsert_device_alias(db.init_db(), address, friendly, source="probe")
            except Exception:
                pass
            for svc in client.services:
                for ch in svc.characteristics:
                    info = CharacteristicInfo(
                        service_uuid=svc.uuid,
                        char_uuid=ch.uuid,
                        handle=getattr(ch, "handle", None),
                        properties=list(ch.properties),
                    )
                    if "read" in ch.properties and read_all_readable:
                        try:
                            v = await client.read_gatt_char(ch.uuid)
                            info.read_value_hex = bytes(v).hex()
                            _record_packet("peripheral->central", info.handle, bytes(v),
                                           0x0B, "ATT_READ_RSP")
                            # Standard Device Name characteristic = 0x2A00.
                            # If we read it, learn the name for the alias DB.
                            if ch.uuid.lower().startswith("00002a00"):
                                try:
                                    name = bytes(v).decode("utf-8", errors="replace").strip("\x00")
                                    if name:
                                        result.device_name = result.device_name or name
                                        db.upsert_device_alias(db.init_db(), address, name, source="probe")
                                except Exception:
                                    pass
                        except Exception as exc:
                            info.read_error = str(exc)
                    if "notify" in ch.properties or "indicate" in ch.properties:
                        try:
                            await client.start_notify(ch.uuid, _cb_for(ch.uuid, info.handle))
                        except Exception as exc:
                            log.debug("start_notify(%s) failed: %s", ch.uuid, exc)
                    result.characteristics.append(info)

            # Linger to collect notifications
            await asyncio.sleep(listen_for_notifications_ms / 1000.0)

            # Stop notifies
            for ch_info in result.characteristics:
                if any(prop in ch_info.properties for prop in ("notify", "indicate")):
                    try:
                        await client.stop_notify(ch_info.char_uuid)
                    except Exception:
                        pass

            for ch_info in result.characteristics:
                ch_info.notify_received_hex = notifies.get(ch_info.char_uuid, [])
    except Exception as exc:
        result.error = str(exc)

    if conn is not None and session_id is not None:
        db.end_session(conn, session_id)

    result.session_id = session_id
    return result


def scan_sync(duration: float = 5.0) -> list[ScanResult]:
    return asyncio.run(scan(duration))


def probe_sync(address: str, **kw) -> ProbeResult:
    return asyncio.run(probe(address, **kw))
