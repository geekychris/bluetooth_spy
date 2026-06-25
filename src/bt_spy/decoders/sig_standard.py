"""Decoders for Bluetooth SIG-standard services.

These are the well-known characteristic UUIDs every BLE device shares — Battery,
Heart Rate, Device Information, Current Time, Tx Power. Register them by full UUID
so they fire regardless of which device-specific handle they live at.

Keys use the wildcard device "*" and the full 128-bit UUID rather than handle —
this makes them work across every device without per-device config.
"""

import struct

from ..analysis.decoder import register_decoder


# --- Battery Service (0x180F) ---

@register_decoder("*:char:00002a19-0000-1000-8000-00805f9b34fb")
def battery_level(payload: bytes) -> dict:
    """Battery Level (0x2A19) — single uint8, 0..100 percent."""
    if not payload:
        return {"error": "empty payload"}
    return {"battery_percent": payload[0]}


# --- Heart Rate Service (0x180D) ---

@register_decoder("*:char:00002a37-0000-1000-8000-00805f9b34fb")
def heart_rate(payload: bytes) -> dict:
    """Heart Rate Measurement (0x2A37) — flags byte + uint8/uint16 BPM + optional fields."""
    if len(payload) < 2:
        return {"error": "payload too short"}
    flags = payload[0]
    out: dict = {"flags": flags}
    pos = 1
    if flags & 0x01:  # 16-bit BPM
        out["bpm"] = struct.unpack_from("<H", payload, pos)[0]
        pos += 2
    else:  # 8-bit BPM
        out["bpm"] = payload[pos]
        pos += 1
    if flags & 0x02:
        out["sensor_contact"] = bool(flags & 0x02)
    if flags & 0x08 and pos + 2 <= len(payload):
        out["energy_expended_kj"] = struct.unpack_from("<H", payload, pos)[0]
        pos += 2
    return out


# --- Device Information Service (0x180A) ---

@register_decoder("*:char:00002a29-0000-1000-8000-00805f9b34fb")
def manufacturer_name(payload: bytes) -> dict:
    return {"manufacturer_name": payload.decode("utf-8", errors="replace")}


@register_decoder("*:char:00002a24-0000-1000-8000-00805f9b34fb")
def model_number(payload: bytes) -> dict:
    return {"model_number": payload.decode("utf-8", errors="replace")}


@register_decoder("*:char:00002a25-0000-1000-8000-00805f9b34fb")
def serial_number(payload: bytes) -> dict:
    return {"serial_number": payload.decode("utf-8", errors="replace")}


@register_decoder("*:char:00002a26-0000-1000-8000-00805f9b34fb")
def firmware_revision(payload: bytes) -> dict:
    return {"firmware_revision": payload.decode("utf-8", errors="replace")}


@register_decoder("*:char:00002a27-0000-1000-8000-00805f9b34fb")
def hardware_revision(payload: bytes) -> dict:
    return {"hardware_revision": payload.decode("utf-8", errors="replace")}


# --- Generic Access Service (0x1800) ---

@register_decoder("*:char:00002a00-0000-1000-8000-00805f9b34fb")
def device_name(payload: bytes) -> dict:
    return {"device_name": payload.decode("utf-8", errors="replace").strip("\x00")}


# --- Tx Power Service (0x1804) ---

@register_decoder("*:char:00002a07-0000-1000-8000-00805f9b34fb")
def tx_power(payload: bytes) -> dict:
    """Tx Power Level (0x2A07) — single int8, dBm."""
    if not payload:
        return {"error": "empty payload"}
    return {"tx_power_dbm": struct.unpack_from("<b", payload, 0)[0]}


# --- Current Time Service (0x1805) ---

@register_decoder("*:char:00002a2b-0000-1000-8000-00805f9b34fb")
def current_time(payload: bytes) -> dict:
    """Current Time (0x2A2B): year(LE16) month day hours mins secs day_of_week frac sub_index"""
    if len(payload) < 10:
        return {"error": "payload too short"}
    year, month, day, hh, mm, ss, dow, frac, _ = struct.unpack_from("<HBBBBBBBB", payload, 0)
    return {
        "iso": f"{year:04d}-{month:02d}-{day:02d}T{hh:02d}:{mm:02d}:{ss:02d}",
        "day_of_week": dow, "fraction_256": frac,
    }
