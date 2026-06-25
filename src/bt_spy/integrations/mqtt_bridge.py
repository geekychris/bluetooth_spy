"""Bridge a BLE device to MQTT with Home Assistant discovery.

Run as `bt-spy bridge --device MiSmartLight --mqtt mqtt://broker[:port]`.

Architecture:
  - For each protocol_entries.name in the canonical vocabulary, publish an HA
    MQTT discovery config under `homeassistant/<platform>/<node>/<entry>/config`.
  - Subscribe to `<base>/<entry>/set` for each write entry.
  - Connect to the BLE device via bleak, subscribe to notify-able characteristics
    that we have decoders for, and publish their decoded values to
    `<base>/<entry>/state`.

This is the "no HA-side code" path: you drop a broker URL in, and HA picks up
the entities automatically via MQTT discovery.

Dependency: requires `aiomqtt` (install with `pip install aiomqtt`).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from .. import db
from . import vocabulary as vocab

log = logging.getLogger(__name__)

DISCOVERY_PREFIX = "homeassistant"


@dataclass
class BridgeConfig:
    device_name: str
    ble_address: str
    mqtt_url: str  # mqtt://user:pass@host:port
    base_topic: str | None = None  # default: bt-spy/<device_slug>
    discovery_prefix: str = DISCOVERY_PREFIX


async def run_bridge(cfg: BridgeConfig) -> None:
    try:
        import aiomqtt
    except ImportError as exc:
        raise RuntimeError(
            "aiomqtt is not installed. Run `pip install aiomqtt` to enable MQTT bridging."
        ) from exc
    from bleak import BleakClient

    entries = db.list_protocol_entries(db.init_db(), device_name=cfg.device_name)
    if not entries:
        raise ValueError(f"No protocol entries for {cfg.device_name!r}")

    base = cfg.base_topic or f"bt-spy/{_slug(cfg.device_name)}"
    parsed = urlparse(cfg.mqtt_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 1883
    user = parsed.username
    password = parsed.password

    write_entries = [e for e in entries if e["direction"] == "central->peripheral" and e["char_uuid"]]
    read_entries = [e for e in entries if e["direction"] != "central->peripheral" and e["char_uuid"]]

    discovery_msgs = list(_discovery_messages(cfg, base, write_entries, read_entries))

    log.info("Connecting to MQTT %s:%s and BLE %s", host, port, cfg.ble_address)

    async with aiomqtt.Client(hostname=host, port=port, username=user, password=password) as mq:
        # Publish discovery configs (retain=True so HA picks them up on (re)start)
        for topic, payload in discovery_msgs:
            await mq.publish(topic, payload=json.dumps(payload), retain=True)

        async with BleakClient(cfg.ble_address, timeout=20.0) as ble:
            # Compile decoders/encoders once
            decoders = {e["char_uuid"]: _compile_decoder(e) for e in read_entries}
            encoders_by_topic = {
                f"{base}/{e['name']}/set": (e["char_uuid"], _compile_encoder(e))
                for e in write_entries
            }

            async def on_notify(sender, data):
                uuid = getattr(sender, "uuid", None) or sender
                dec = decoders.get(uuid)
                if not dec:
                    return
                try:
                    value = dec(bytes(data))
                except Exception as exc:
                    log.warning("decode failed on %s: %s", uuid, exc)
                    return
                # Find the entry name for this uuid to compute the state topic
                entry = next((e for e in read_entries if e["char_uuid"] == uuid), None)
                if not entry:
                    return
                topic = f"{base}/{entry['name']}/state"
                payload = value if isinstance(value, (int, float, bool, str)) else json.dumps(value, default=str)
                await mq.publish(topic, payload=str(payload), retain=True)

            # Subscribe to BLE notifies
            for e in read_entries:
                try:
                    await ble.start_notify(e["char_uuid"], on_notify)
                except Exception as exc:
                    log.debug("start_notify(%s) failed: %s", e["char_uuid"], exc)

            # Subscribe to MQTT command topics
            for topic in encoders_by_topic:
                await mq.subscribe(topic)

            log.info("Bridge running. base topic=%s", base)
            async for message in mq.messages:
                topic_str = str(message.topic)
                pair = encoders_by_topic.get(topic_str)
                if not pair:
                    continue
                uuid, enc = pair
                try:
                    payload = message.payload.decode() if isinstance(message.payload, (bytes, bytearray)) else str(message.payload)
                    raw = enc(payload)
                    await ble.write_gatt_char(uuid, raw, response=False)
                except Exception as exc:
                    log.warning("write %s failed: %s", topic_str, exc)


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name.lower()).strip("_")


def _discovery_messages(cfg: BridgeConfig, base: str, writes, reads):
    """Yield (topic, payload-dict) pairs for HA MQTT discovery."""
    dev_block = {
        "identifiers": [cfg.ble_address],
        "name": cfg.device_name,
        "manufacturer": "Unknown",
        "model": cfg.device_name,
    }
    node = _slug(cfg.device_name)
    write_buckets = vocab.classify_writes([e["name"] for e in writes])

    # Lights / switches / etc. from write buckets
    if "light" in write_buckets:
        names = write_buckets["light"]
        cmd_t = f"{base}/{names[0]}/set"
        cfg_payload = {
            "name": cfg.device_name,
            "unique_id": f"{node}_light",
            "command_topic": cmd_t,
            "schema": "json",
            "brightness": "set_brightness" in names,
            "rgb": "set_color_rgb" in names,
            "device": dev_block,
        }
        yield f"{cfg.discovery_prefix}/light/{node}/light/config", cfg_payload
    if "switch" in write_buckets:
        cmd_t = f"{base}/{write_buckets['switch'][0]}/set"
        yield f"{cfg.discovery_prefix}/switch/{node}/sw/config", {
            "name": cfg.device_name,
            "unique_id": f"{node}_sw",
            "command_topic": cmd_t,
            "payload_on": "1",
            "payload_off": "0",
            "device": dev_block,
        }

    # Sensors from read buckets
    for e in reads:
        spec = vocab.READS_TO_PLATFORM.get(e["name"])
        if not spec:
            continue
        platform, _, attrs = spec
        state_t = f"{base}/{e['name']}/state"
        payload = {
            "name": e["name"].replace("_", " ").title(),
            "unique_id": f"{node}_{e['name']}",
            "state_topic": state_t,
            "device": dev_block,
        }
        if "unit" in attrs:
            payload["unit_of_measurement"] = attrs["unit"]
        if "device_class" in attrs:
            payload["device_class"] = attrs["device_class"]
        yield f"{cfg.discovery_prefix}/{platform}/{node}/{e['name']}/config", payload


def _compile_decoder(entry):
    snippet = entry["decoder_py"]
    if not snippet:
        return lambda p: p.hex()
    ns: dict = {}
    exec(snippet, {"__builtins__": __builtins__}, ns)
    return ns.get("decode", lambda p: p.hex())


def _compile_encoder(entry):
    snippet = entry["encoder_py"]
    if snippet:
        ns: dict = {}
        exec(snippet, {"__builtins__": __builtins__}, ns)
        if "encode" in ns:
            fn = ns["encode"]
            # accept any single string/json arg, route through encode
            def _wrap(payload_str):
                try:
                    arg = json.loads(payload_str)
                except Exception:
                    arg = payload_str
                if isinstance(arg, dict):
                    return fn(**arg)
                return fn(arg)
            return _wrap
    # Default: assume MQTT sends hex string
    return lambda s: bytes.fromhex(s.strip())


def run_blocking(cfg: BridgeConfig) -> None:
    asyncio.run(run_bridge(cfg))
