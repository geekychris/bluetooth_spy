"""Example built-in decoder: standard BLE Battery Service notification.

The Battery Service (0x180F) exposes a single Battery Level characteristic that
notifies a 1-byte percentage 0..100. We register against handle wildcard "*"
because the actual handle is device-specific.

This file exists as a worked example — duplicate it for each protocol you reverse
engineer, give it a unique key, and import its functions from your code or MCP tool.
"""

from ..analysis.decoder import register_decoder


@register_decoder("*:battery_level:peripheral->central")
def decode_battery_level(payload: bytes) -> dict:
    if not payload:
        return {"error": "empty payload"}
    return {"battery_percent": payload[0]}
