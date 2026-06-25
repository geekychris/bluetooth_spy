"""pcap-ng reader + scapy-based BTLE / HCI / ATT decoder.

We deliberately do the pcap-ng parsing by hand (it's small) rather than pulling
in `python-pcapng`. The output of each `iter_frames` step is `(timestamp, raw_bytes)`.
Decoding is layered: try BTLE first (what the OTA sniffer emits), fall back to
generic linktype-based handling.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterator

# pcap-ng block types
BLOCK_TYPE_SHB = 0x0A0D0D0A
BLOCK_TYPE_IDB = 0x00000001
BLOCK_TYPE_EPB = 0x00000006
BLOCK_TYPE_SPB = 0x00000003

# Common linktypes
LINKTYPE_BLUETOOTH_LE_LL = 251
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256
LINKTYPE_BLUETOOTH_HCI_H4 = 187
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
LINKTYPE_NORDIC_BLE = 272   # Nordic's own pcap linktype; emitted by `nrfutil ble-sniffer sniff`
NORDIC_BLE_PREFIX_LEN = 17  # nrfutil ble-sniffer v0.19/0.20 protocol_version=3 header is 17 bytes


@dataclass
class Frame:
    timestamp: float       # seconds since epoch
    linktype: int
    raw: bytes
    decoded: dict[str, Any] = field(default_factory=dict)


def iter_pcap_classic_tail(
    path,
    *,
    stop_event=None,
    poll_interval_s: float = 0.05,
    initial_wait_s: float = 5.0,
) -> Iterator[Frame]:
    """Tail a classic-pcap file that nrfutil ble-sniffer is incrementally writing.

    Reads the 24-byte global header once, then loops reading 16-byte per-packet
    headers + their captured bytes, sleeping briefly at EOF. Same shape as
    iter_pklg_tail but for the classic pcap on-disk format.
    """
    import threading
    import time as _time
    from pathlib import Path as _Path
    p = _Path(path)
    deadline = _time.monotonic() + initial_wait_s
    while not p.exists() or p.stat().st_size < 24:
        if stop_event and stop_event.is_set():
            return
        if _time.monotonic() > deadline:
            raise FileNotFoundError(
                f"nrfutil pcap file {p} didn't appear within {initial_wait_s}s. "
                "Is the sniffer running and writing?"
            )
        _time.sleep(0.05)

    with open(p, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return
        # Magic byte order tells us file byte order.
        # If we read 4 bytes and get 0xa1b2c3d4 little-endian, the file is LE.
        # If those same bytes read as big-endian also give 0xa1b2c3d4, the file is BE.
        # Test both: pick the order in which the magic is recognized.
        le_magic = struct.unpack("<I", global_header[:4])[0]
        be_magic = struct.unpack(">I", global_header[:4])[0]
        if le_magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif be_magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = ">"
        else:
            raise ValueError(f"Not a pcap file: bad magic {global_header[:4].hex()}")
        linktype = struct.unpack(f"{endian}I", global_header[20:24])[0]

        buf = b""
        while True:
            if stop_event and stop_event.is_set():
                return
            while len(buf) < 16:
                more = f.read(8192)
                if more:
                    buf += more
                    continue
                if stop_event and stop_event.is_set():
                    return
                _time.sleep(poll_interval_s)
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(f"{endian}IIII", buf[:16])
            total = 16 + incl_len
            while len(buf) < total:
                more = f.read(8192)
                if more:
                    buf += more
                    continue
                if stop_event and stop_event.is_set():
                    return
                _time.sleep(poll_interval_s)
            raw = buf[16:total]
            buf = buf[total:]
            yield Frame(
                timestamp=ts_sec + ts_usec / 1_000_000.0,
                linktype=linktype,
                raw=raw,
            )


def iter_pcapng_frames(stream: BinaryIO) -> Iterator[Frame]:
    """Yield Frame objects from a pcap-ng stream.

    Tolerant of partial blocks: if the read returns 0 bytes mid-stream, stops cleanly.
    """
    interfaces: list[dict[str, Any]] = []
    while True:
        header = stream.read(8)
        if len(header) < 8:
            return
        block_type, block_total_len = struct.unpack("<II", header)
        body_len = block_total_len - 12
        body = stream.read(body_len)
        trailer = stream.read(4)
        if len(body) < body_len or len(trailer) < 4:
            return

        if block_type == BLOCK_TYPE_SHB:
            # Section Header — could be big-endian; we assume little-endian (Nordic + Linux).
            continue
        elif block_type == BLOCK_TYPE_IDB:
            linktype, _, snaplen = struct.unpack("<HHI", body[:8])
            interfaces.append({"linktype": linktype, "snaplen": snaplen})
        elif block_type == BLOCK_TYPE_EPB:
            (iface_id, ts_high, ts_low, captured_len, _orig_len) = struct.unpack(
                "<IIIII", body[:20]
            )
            packet = body[20 : 20 + captured_len]
            ts = ((ts_high << 32) | ts_low) / 1_000_000.0  # microseconds resolution
            lt = interfaces[iface_id]["linktype"] if iface_id < len(interfaces) else 0
            yield Frame(timestamp=ts, linktype=lt, raw=packet)
        elif block_type == BLOCK_TYPE_SPB:
            (orig_len,) = struct.unpack("<I", body[:4])
            packet = body[4 : 4 + orig_len]
            lt = interfaces[0]["linktype"] if interfaces else 0
            yield Frame(timestamp=0.0, linktype=lt, raw=packet)
        # Unknown block types are silently skipped — pcap-ng is extensible.


# ---------- Decoding ----------

# We use scapy lazily so the package imports fast and so that running --doctor
# without scapy installed at least reports a sensible error.
def _scapy_btle():
    from scapy.layers import bluetooth4LE  # noqa: F401
    from scapy.layers.bluetooth4LE import BTLE, BTLE_DATA, BTLE_ADV  # noqa: F401
    from scapy.layers.bluetooth import (  # noqa: F401
        ATT_Hdr,
        ATT_Write_Request,
        ATT_Write_Command,
        ATT_Read_Request,
        ATT_Read_Response,
        ATT_Handle_Value_Notification,
        ATT_Handle_Value_Indication,
    )
    return bluetooth4LE


# Mapping ATT opcodes → human label / typed direction hint.
ATT_OPCODES: dict[int, tuple[str, str]] = {
    0x01: ("ATT_ERROR_RSP", "peripheral->central"),
    0x02: ("ATT_EXCHANGE_MTU_REQ", "central->peripheral"),
    0x03: ("ATT_EXCHANGE_MTU_RSP", "peripheral->central"),
    0x08: ("ATT_READ_BY_TYPE_REQ", "central->peripheral"),
    0x09: ("ATT_READ_BY_TYPE_RSP", "peripheral->central"),
    0x0A: ("ATT_READ_REQ", "central->peripheral"),
    0x0B: ("ATT_READ_RSP", "peripheral->central"),
    0x12: ("ATT_WRITE_REQ", "central->peripheral"),
    0x13: ("ATT_WRITE_RSP", "peripheral->central"),
    0x52: ("ATT_WRITE_CMD", "central->peripheral"),
    0x1B: ("ATT_HANDLE_VALUE_NTF", "peripheral->central"),
    0x1D: ("ATT_HANDLE_VALUE_IND", "peripheral->central"),
    0x1E: ("ATT_HANDLE_VALUE_CFM", "central->peripheral"),
}


@dataclass
class DecodedPacket:
    pdu_type: str | None
    direction: str | None
    handle: int | None        # ATT handle (GATT-level)
    opcode: int | None
    payload: bytes | None
    summary: dict[str, Any]
    conn_handle: int | None = None  # BLE link-layer connection handle (HCI ACL)
    device_addr: str | None = None   # BD_ADDR (BLE device identifier), e.g. 'AA:BB:CC:DD:EE:FF'
    device_name: str | None = None   # local name from advertising data, when present


def decode_btle(raw: bytes) -> DecodedPacket:
    """Best-effort decode of an over-the-air BLE link-layer frame.

    Use for `LINKTYPE_BLUETOOTH_LE_LL[*]` — what the nRF sniffer emits. For HCI
    frames (PacketLogger output), use decode_hci.
    """
    summary: dict[str, Any] = {"raw_hex": raw.hex(), "len": len(raw)}
    pdu_type = direction = None
    handle = opcode = None
    payload: bytes | None = None
    device_addr: str | None = None

    try:
        bluetooth4LE = _scapy_btle()
        BTLE = bluetooth4LE.BTLE
        try:
            pkt = BTLE(raw)
        except Exception:
            pkt = None
        if pkt is not None:
            summary["scapy_summary"] = pkt.summary()
            for layer in _layer_iter(pkt):
                cls_name = type(layer).__name__
                summary.setdefault("layers", []).append(cls_name)
                if cls_name.startswith("ATT_"):
                    handle = getattr(layer, "gatt_handle", handle)
                    handle = getattr(layer, "handle", handle)
                    opcode = getattr(layer, "opcode", opcode)
                    for f in ("data", "value", "Data"):
                        if hasattr(layer, f):
                            v = getattr(layer, f)
                            if isinstance(v, (bytes, bytearray)):
                                payload = bytes(v)
                                break
                    pdu_type = cls_name
                if cls_name.startswith("BTLE_ADV") or cls_name == "BTLE_SCAN_RSP":
                    pdu_type = cls_name
                    direction = "adv"
                    # Advertising layers carry the advertiser address (AdvA).
                    for f in ("AdvA", "InitA", "ScanA", "address"):
                        if hasattr(layer, f):
                            v = getattr(layer, f)
                            s = _addr_str(v)
                            if s:
                                device_addr = device_addr or s
                                break
    except Exception as exc:
        summary["decode_error"] = str(exc)

    if opcode in ATT_OPCODES:
        name, dir_hint = ATT_OPCODES[opcode]
        pdu_type = pdu_type or name
        direction = direction or dir_hint

    return DecodedPacket(
        pdu_type=pdu_type, direction=direction,
        handle=handle, opcode=opcode, payload=payload, summary=summary,
        device_addr=device_addr,
    )


def decode_hci(raw: bytes, direction_hint: str | None = None) -> DecodedPacket:
    """Decode an HCI H4 frame (indicator-prefixed). What PacketLogger emits.

    Walks HCI_Hdr → HCI_ACL_Hdr → L2CAP_Hdr → ATT_Hdr and pulls the ATT details
    we use everywhere else (handle, opcode, payload). For CMD/EVT frames we
    record the layer name but leave handle/payload empty — those are HCI control,
    not GATT.
    """
    summary: dict[str, Any] = {"raw_hex": raw.hex(), "len": len(raw)}
    pdu_type = None
    handle = opcode = None
    payload: bytes | None = None

    if not raw:
        return DecodedPacket(None, direction_hint, None, None, None, summary)

    indicator = raw[0]
    summary["h4_indicator"] = indicator
    direction = direction_hint

    conn_handle = None
    device_addr = None
    device_name = None
    try:
        from scapy.layers.bluetooth import HCI_Hdr  # noqa: F401
        pkt = HCI_Hdr(raw)
        summary["scapy_summary"] = pkt.summary()
        for layer in _layer_iter(pkt):
            cls_name = type(layer).__name__
            summary.setdefault("layers", []).append(cls_name)
            # HCI ACL layer carries the link-layer connection handle — that's our
            # "which device" identifier for connected traffic.
            if cls_name == "HCI_ACL_Hdr":
                conn_handle = getattr(layer, "handle", conn_handle)
            # Advertising reports carry the advertiser's BD_ADDR per report,
            # and often a Complete Local Name AD record.
            if "Advertising_Report" in cls_name or "Advertising_Reports" in cls_name:
                addr = _extract_adv_address(layer)
                if addr:
                    device_addr = device_addr or addr
                name = _extract_adv_name(layer)
                if name:
                    device_name = device_name or name
            # LE Meta Connection Complete (subevent 0x01) carries (conn_handle, peer_address)
            # — this is what lets us map subsequent ACL packets to a device.
            if cls_name == "HCI_LE_Meta_Connection_Complete":
                addr = getattr(layer, "paddr", None) or getattr(layer, "peer_address", None)
                if addr:
                    device_addr = device_addr or _addr_str(addr)
                if conn_handle is None:
                    ch = getattr(layer, "handle", None)
                    if ch is not None:
                        conn_handle = ch
            # ATT layer is the payload-bearing one we care about for GATT.
            if cls_name.startswith("ATT_"):
                pdu_type = pdu_type or cls_name
                # ATT handle is GATT-level; NOT the same as HCI_ACL_Hdr.handle
                att_handle = getattr(layer, "gatt_handle", None)
                if att_handle is None:
                    att_handle = getattr(layer, "handle", None)
                if att_handle is not None and cls_name != "HCI_ACL_Hdr":
                    handle = att_handle
                opcode = getattr(layer, "opcode", opcode)
                for f in ("data", "value", "Data"):
                    if hasattr(layer, f):
                        v = getattr(layer, f)
                        if isinstance(v, (bytes, bytearray)):
                            payload = bytes(v)
                            break
            elif cls_name in ("HCI_Command_Hdr", "HCI_Event_Hdr"):
                pdu_type = pdu_type or cls_name
    except Exception as exc:
        summary["decode_error"] = str(exc)

    if opcode in ATT_OPCODES:
        name, dir_hint = ATT_OPCODES[opcode]
        pdu_type = pdu_type or name
        # PacketLogger's direction_hint is authoritative; only fall back to opcode hint.
        direction = direction or dir_hint

    return DecodedPacket(
        pdu_type=pdu_type, direction=direction,
        handle=handle, opcode=opcode, payload=payload, summary=summary,
        conn_handle=conn_handle, device_addr=device_addr, device_name=device_name,
    )


def _addr_str(addr) -> str | None:
    """Normalize a scapy BD_ADDR field to 'AA:BB:CC:DD:EE:FF' uppercase."""
    if addr is None:
        return None
    if isinstance(addr, (bytes, bytearray)):
        if len(addr) != 6:
            return None
        return ":".join(f"{b:02X}" for b in reversed(bytes(addr)))
    s = str(addr).upper()
    # scapy often returns e.g. 'aa:bb:cc:dd:ee:ff' already
    if len(s) == 17 and s.count(":") == 5:
        return s
    return None


def _extract_adv_address(layer) -> str | None:
    """Pull a BD_ADDR out of an LE Advertising Report layer.

    The Extended Advertising Reports layer carries a `reports` list of items,
    each with an `address` field. Legacy Advertising Reports has the field
    directly on the layer. We try both shapes.
    """
    # Single-report case (legacy)
    for f in ("address", "advertising_address", "addr"):
        if hasattr(layer, f):
            v = getattr(layer, f)
            s = _addr_str(v)
            if s:
                return s
    # Multi-report case (extended)
    reports = getattr(layer, "reports", None)
    if reports:
        try:
            first = reports[0]
            for f in ("address", "addr", "advertising_address"):
                if hasattr(first, f):
                    return _addr_str(getattr(first, f))
        except Exception:
            return None
    return None


def _extract_adv_name(layer) -> str | None:
    """Pull a UTF-8 device name from advertising data, if the advertiser broadcast one.

    Two shapes to handle:
      - Raw bytes: walk AD records `[length, type, value]`. Type 0x09 / 0x08.
      - scapy-parsed list of EIR_Hdr packets: look for EIR_CompleteLocalName / Shortened.

    Returns the first Complete name found, falling back to Shortened.
    """
    # Try the scapy-parsed shape first — it's what extended adv reports give us.
    name = _name_from_eir_list(layer)
    if name:
        return name
    # Fall back to raw bytes parser
    data = _extract_adv_data(layer)
    if data:
        return _parse_ad_records_for_name(data)
    return None


def _name_from_eir_list(layer) -> str | None:
    """If `layer.data` (or a report's `data`) is a list of EIR_Hdr packets, scan for a local name."""
    def scan(items) -> tuple[str | None, str | None]:
        complete = shortened = None
        for h in items:
            inner = getattr(h, "payload", None) or h
            cls = type(inner).__name__
            if cls == "EIR_CompleteLocalName":
                complete = complete or _get_local_name_field(inner)
            elif cls == "EIR_ShortenedLocalName":
                shortened = shortened or _get_local_name_field(inner)
        return complete, shortened

    # Direct layer.data list (legacy reports often)
    data = getattr(layer, "data", None)
    if isinstance(data, list) and data:
        complete, shortened = scan(data)
        if complete or shortened:
            return complete or shortened

    # Extended reports nested in `reports`
    reports = getattr(layer, "reports", None)
    if reports:
        try:
            first = reports[0]
            data = getattr(first, "data", None)
            if isinstance(data, list) and data:
                complete, shortened = scan(data)
                if complete or shortened:
                    return complete or shortened
        except Exception:
            return None
    return None


def _get_local_name_field(eir) -> str | None:
    """EIR_CompleteLocalName / Shortened expose the string under different field names
    across scapy versions. Try the broad set."""
    for f in ("local_name", "device_name", "name", "complete_local_name"):
        v = getattr(eir, f, None)
        if isinstance(v, (bytes, bytearray)):
            return v.decode("utf-8", errors="replace").strip("\x00") or None
        if isinstance(v, str):
            return v.strip("\x00") or None
    return None


def _extract_adv_data(layer) -> bytes | None:
    """Find the raw advertising-data byte string on an LE advertising-report layer."""
    # Legacy reports: `data` is directly on the layer
    for f in ("data", "adv_data"):
        if hasattr(layer, f):
            v = getattr(layer, f)
            if isinstance(v, (bytes, bytearray)) and v:
                return bytes(v)
    # Extended reports: each report carries its own data
    reports = getattr(layer, "reports", None)
    if reports:
        try:
            first = reports[0]
            for f in ("data", "adv_data", "advertising_data"):
                if hasattr(first, f):
                    v = getattr(first, f)
                    if isinstance(v, (bytes, bytearray)) and v:
                        return bytes(v)
        except Exception:
            return None
    return None


def _parse_ad_records_for_name(data: bytes) -> str | None:
    """Walk AD records looking for a local name. Tolerant of malformed records."""
    short = None
    i = 0
    while i < len(data):
        length = data[i]
        if length == 0:
            i += 1
            continue
        if i + 1 + length > len(data):
            return short
        ad_type = data[i + 1]
        value = data[i + 2 : i + 1 + length]
        if ad_type == 0x09:  # Complete Local Name
            try:
                return value.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                pass
        elif ad_type == 0x08 and short is None:  # Shortened Local Name
            try:
                short = value.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                pass
        i += 1 + length
    return short


def decode_frame(frame: "Frame") -> DecodedPacket:
    """Route a Frame to the right decoder based on its linktype.

    Supported linktypes:
      - LINKTYPE_BLUETOOTH_HCI_H4 (187) / _WITH_PHDR (201) — PL.app captures
      - LINKTYPE_BLUETOOTH_LE_LL (251) — raw OTA BLE link layer
      - LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256) — same + 10-byte pseudo-header
      - LINKTYPE_NORDIC_BLE (272) — nrfutil ble-sniffer's Nordic-specific pseudo-header
    """
    if frame.linktype in (LINKTYPE_BLUETOOTH_HCI_H4, LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR):
        return decode_hci(frame.raw, direction_hint=frame.decoded.get("direction_hint"))
    if frame.linktype == LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
        return _decode_btle_with_phdr(frame.raw)
    if frame.linktype == LINKTYPE_NORDIC_BLE:
        return _decode_nordic_ble(frame.raw)
    return decode_btle(frame.raw)


def _decode_nordic_ble(raw: bytes) -> DecodedPacket:
    """Strip Nordic's 17-byte pseudo-header (board_id + counter + flags + channel + RSSI + delta_time)
    and decode the BLE LL PDU that follows.

    Format (protocol version 3, as emitted by nrfutil ble-sniffer 0.19+):
        +0:   board_id (0xCD for nRF52840 Dongle)
        +1:   length byte
        +2:   reserved
        +3:   protocol version
        +4-5: packet counter (LE)
        +6:   id
        +7-8: flags / channel
        +9:   RSSI (signed)
        +10-12: event/timing fields
        +13-16: delta time / extras
        +17+:  BLE Link Layer PDU
    """
    if len(raw) < NORDIC_BLE_PREFIX_LEN:
        return DecodedPacket(
            pdu_type=None, direction=None, handle=None, opcode=None, payload=None,
            summary={"raw_hex": raw.hex(), "decode_error": f"frame shorter than Nordic prefix ({len(raw)} < 17)"},
        )
    inner = raw[NORDIC_BLE_PREFIX_LEN:]
    decoded = decode_btle(inner)
    # Surface select metadata from the Nordic prefix
    decoded.summary.update({
        "nordic_board_id": raw[0],
        "nordic_protover": raw[3] if len(raw) > 3 else None,
        "nordic_channel": raw[8] if len(raw) > 8 else None,
        # Nordic stores RSSI as positive magnitude; convention is negative dBm.
        "nordic_rssi_dbm": -raw[9] if len(raw) > 9 else None,
        "raw_hex": raw.hex(),
        "ll_raw_hex": inner.hex(),
    })
    return decoded


def _decode_btle_with_phdr(raw: bytes) -> DecodedPacket:
    """Parse the 10-byte BLE LL pseudo-header, then decode the rest as BLE LL.

    PHDR layout (10 bytes, little-endian where relevant):
        +0: rf_channel (uint8)
        +1: signal_power dBm (int8)
        +2: noise_power dBm (int8)
        +3: access_address_offenses (uint8)
        +4: reference_access_address (uint32 LE)
        +8: flags (uint16 LE)
    """
    if len(raw) < 10:
        return DecodedPacket(
            pdu_type=None, direction=None, handle=None, opcode=None, payload=None,
            summary={"raw_hex": raw.hex(), "len": len(raw), "decode_error": "frame shorter than PHDR"},
        )
    import struct as _struct
    rf_channel = raw[0]
    rssi_dbm = _struct.unpack_from("<b", raw, 1)[0]
    noise_dbm = _struct.unpack_from("<b", raw, 2)[0]
    aa_offenses = raw[3]
    ref_aa = _struct.unpack_from("<I", raw, 4)[0]
    flags = _struct.unpack_from("<H", raw, 8)[0]

    inner = raw[10:]
    decoded = decode_btle(inner)
    decoded.summary.update({
        "phdr_rf_channel": rf_channel,
        "phdr_rssi_dbm": rssi_dbm,
        "phdr_noise_dbm": noise_dbm,
        "phdr_ref_access_address": f"0x{ref_aa:08x}",
        "phdr_flags": f"0x{flags:04x}",
        "phdr_aa_offenses": aa_offenses,
        "raw_hex": raw.hex(),
        "ll_raw_hex": inner.hex(),
    })
    return decoded


def _layer_iter(pkt) -> Iterator[Any]:
    cur = pkt
    while cur is not None:
        yield cur
        cur = cur.payload if getattr(cur, "payload", None) else None
        if cur is not None and type(cur).__name__ == "NoPayload":
            return
