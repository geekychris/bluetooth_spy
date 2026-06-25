"""Canonical protocol-entry names and how each maps to a Home Assistant platform.

Use these names verbatim in `protocol_entries.name` when you want zero-touch HA
scaffolding. Anything outside this list still gets a driver method but lands as
a TODO in the scaffolded integration.

Two views:
  - WRITES_TO_PLATFORM: c->p writes that should become controllable HA entities.
  - READS_TO_PLATFORM:  p->c notifies/reads that should become reporting entities.

Multiple writes can roll up into the same platform (`power` + `set_brightness`
→ one light entity), so the scaffolder groups by platform, not by entry.
"""

from __future__ import annotations

# Each entry maps a canonical name → (platform, role).
# `role` tells the scaffolder how to wire it on the entity:
#   - "primary_on_off": the main on/off control for the platform
#   - "brightness", "color_rgb", "color_temp": light attributes
#   - "position", "tilt": cover attributes
#   - "speed", "preset": fan attributes
#   - "target_temp", "hvac_mode": climate attributes
#   - "value": single-value sensor / binary_sensor
#   - "event": fires an HA event

WRITES_TO_PLATFORM: dict[str, tuple[str, str]] = {
    "power":               ("switch", "primary_on_off"),
    "set_state":           ("switch", "primary_on_off"),
    "set_brightness":      ("light",  "brightness"),
    "set_color_rgb":       ("light",  "color_rgb"),
    "set_color_temp":      ("light",  "color_temp"),
    "light_on":            ("light",  "primary_on_off"),
    "set_position":        ("cover",  "position"),
    "set_tilt":            ("cover",  "tilt"),
    "cover_open":          ("cover",  "primary_on_off"),
    "set_fan_speed":       ("fan",    "speed"),
    "set_fan_preset":      ("fan",    "preset"),
    "fan_on":              ("fan",    "primary_on_off"),
    "set_target_temperature": ("climate", "target_temp"),
    "set_hvac_mode":       ("climate", "hvac_mode"),
    "lock":                ("lock",   "primary_on_off"),
    "unlock":              ("lock",   "primary_on_off"),
}

READS_TO_PLATFORM: dict[str, tuple[str, str, dict]] = {
    # name → (platform, role, extra HA attributes the entity should report)
    "battery_level":   ("sensor",        "value", {"device_class": "battery",      "unit": "%"}),
    "temperature":     ("sensor",        "value", {"device_class": "temperature",  "unit": "°C"}),
    "humidity":        ("sensor",        "value", {"device_class": "humidity",     "unit": "%"}),
    "illuminance":     ("sensor",        "value", {"device_class": "illuminance",  "unit": "lx"}),
    "power_watts":     ("sensor",        "value", {"device_class": "power",        "unit": "W"}),
    "voltage":         ("sensor",        "value", {"device_class": "voltage",      "unit": "V"}),
    "current":         ("sensor",        "value", {"device_class": "current",      "unit": "A"}),
    "energy_kwh":      ("sensor",        "value", {"device_class": "energy",       "unit": "kWh"}),
    "co2":             ("sensor",        "value", {"device_class": "carbon_dioxide","unit": "ppm"}),
    "rssi":            ("sensor",        "value", {"device_class": "signal_strength","unit": "dBm"}),
    "state":           ("sensor",        "value", {}),
    "motion_detected": ("binary_sensor", "value", {"device_class": "motion"}),
    "door_open":       ("binary_sensor", "value", {"device_class": "door"}),
    "window_open":     ("binary_sensor", "value", {"device_class": "window"}),
    "occupancy":       ("binary_sensor", "value", {"device_class": "occupancy"}),
    "tampered":        ("binary_sensor", "value", {"device_class": "tamper"}),
    "smoke":           ("binary_sensor", "value", {"device_class": "smoke"}),
    "button_pressed":  ("event",         "event", {}),
}


def classify_writes(entry_names: list[str]) -> dict[str, list[str]]:
    """Group write entry names by HA platform.

    >>> classify_writes(["power", "set_brightness", "unknown"])
    {'light': ['power', 'set_brightness'], 'unknown': ['unknown']}

    The 'unknown' bucket is what the scaffolder leaves as a TODO. Note: if
    `power` co-occurs with light-only writes (set_brightness, set_color_rgb),
    we treat power as the light's on/off rather than spawning a separate
    switch entity — see `coalesce_writes`.
    """
    out: dict[str, list[str]] = {}
    for name in entry_names:
        platform = WRITES_TO_PLATFORM.get(name, ("unknown", ""))[0]
        out.setdefault(platform, []).append(name)
    return coalesce_writes(out)


def coalesce_writes(by_platform: dict[str, list[str]]) -> dict[str, list[str]]:
    """If `switch` shares device with `light`/`fan`/`cover`, fold its primary_on_off
    into that richer platform. Avoids 'phantom switch' entities."""
    rich = {"light", "fan", "cover", "climate"}
    present_rich = [p for p in rich if p in by_platform]
    if "switch" in by_platform and present_rich:
        target = present_rich[0]
        by_platform[target] = list(dict.fromkeys(by_platform[target] + by_platform.pop("switch")))
    return by_platform


def classify_reads(entry_names: list[str]) -> dict[str, list[str]]:
    """Group read entry names by HA platform (sensor / binary_sensor / event / unknown)."""
    out: dict[str, list[str]] = {}
    for name in entry_names:
        platform = READS_TO_PLATFORM.get(name, ("unknown", "", {}))[0]
        out.setdefault(platform, []).append(name)
    return out


def all_known_names() -> list[str]:
    return sorted(set(WRITES_TO_PLATFORM) | set(READS_TO_PLATFORM))
