"""MCP server exposing bt-spy capabilities to Claude.

Add to your Claude Code config (~/.claude.json or via `claude mcp add`):

    {
      "mcpServers": {
        "bt-spy": {
          "command": "bt-spy",
          "args": ["mcp"]
        }
      }
    }

Tools exposed:
  list_sessions          — capture sessions metadata
  get_packets            — packets in a session, with filters
  diff_sessions          — what's new in candidate vs baseline
  handle_summary         — frequency + variability per (handle, direction)
  infer_structure        — naive field segmentation for a (session, handle)
  add_annotation         — mark a packet range with a label
  upsert_protocol_entry  — save a (handle, structure, decoder) into the protocol dict
  list_protocol_entries  — read the protocol dict
  replay                 — send a sequence of writes to a real device, optionally mutated
  flash_dongle           — flash the connected nRF52840 with sniffer firmware
  start_capture          — begin a capture session
  stop_capture           — end the current capture session
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .. import db
from ..analysis import diff as diffmod
from ..capture.daemon import CaptureDaemon
from ..config import settings
from ..firmware import flasher
from ..replay.engine import ReplayStep, run_replay

log = logging.getLogger(__name__)

# A single daemon shared across the MCP process. Useful for mcp-launched captures;
# when bt-spy serve is running too, prefer the REST API for captures.
_daemon: CaptureDaemon | None = None


def _json_safe_packets(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        d = dict(r)
        if d.get("payload") is not None:
            d["payload_hex"] = bytes(d["payload"]).hex()
            d.pop("payload", None)
        if d.get("raw") is not None:
            d["raw_hex"] = bytes(d["raw"]).hex()
            d.pop("raw", None)
        out.append(d)
    return out


def build_server() -> Server:
    server = Server("bt-spy")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="list_sessions",
                description="List all capture sessions with metadata.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="get_packets",
                description=(
                    "Return packets from a session, with optional filters by handle, direction "
                    "(adv|central->peripheral|peripheral->central), pdu_type, and a hard limit."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "integer"},
                        "handle": {"type": "integer"},
                        "direction": {"type": "string"},
                        "pdu_type": {"type": "string"},
                        "limit": {"type": "integer", "default": 200},
                    },
                    "required": ["session_id"],
                },
            ),
            Tool(
                name="diff_sessions",
                description="Return packets in `candidate` whose (handle, direction, payload) didn't appear in `baseline`. Use to surface what an action newly triggered.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "baseline_session_id": {"type": "integer"},
                        "candidate_session_id": {"type": "integer"},
                    },
                    "required": ["baseline_session_id", "candidate_session_id"],
                },
            ),
            Tool(
                name="handle_summary",
                description="For each (handle, direction) in a session: count, unique payloads, byte-variability profile.",
                inputSchema={
                    "type": "object",
                    "properties": {"session_id": {"type": "integer"}},
                    "required": ["session_id"],
                },
            ),
            Tool(
                name="infer_structure",
                description="Naive field segmentation for one (session, handle, direction). Useful as a starting hypothesis for what fields the payload encodes.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "integer"},
                        "handle": {"type": "integer"},
                        "direction": {"type": "string"},
                    },
                    "required": ["session_id", "handle"],
                },
            ),
            Tool(
                name="add_annotation",
                description="Tag a contiguous packet range in a session with a label and notes.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "integer"},
                        "packet_id_start": {"type": "integer"},
                        "packet_id_end": {"type": "integer"},
                        "label": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                    "required": ["session_id", "packet_id_start", "packet_id_end", "label"],
                },
            ),
            Tool(
                name="upsert_protocol_entry",
                description="Save (device, handle, direction, name, structure, decoder/encoder snippets) into the persistent protocol dictionary.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "device_name": {"type": "string"},
                        "handle": {"type": "integer"},
                        "direction": {"type": "string"},
                        "name": {"type": "string"},
                        "structure": {"type": "array"},
                        "decoder_py": {"type": "string"},
                        "encoder_py": {"type": "string"},
                        "confidence": {"type": "number"},
                        "notes": {"type": "string"},
                    },
                    "required": ["handle", "direction", "name"],
                },
            ),
            Tool(
                name="list_protocol_entries",
                description="List all entries in the protocol dictionary, newest first.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="replay",
                description=(
                    "Connect to a real BLE device and run a list of write steps, with optional "
                    "mutations. Target may be a name (we'll scan) or a CoreBluetooth UUID. "
                    "Each step: {handle?, char_uuid?, payload_hex, delay_before_ms?, write_with_response?, mutation?}. "
                    "Mutation example: {strategy:'set_byte', offset:2, value:0x80}. "
                    "Returns all writes sent + every notify/indicate received during the listen window."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "steps": {"type": "array"},
                        "session_id": {"type": "integer"},
                        "listen_for_notifications_ms": {"type": "integer", "default": 1000},
                    },
                    "required": ["target", "steps"],
                },
            ),
            Tool(
                name="flash_dongle",
                description="Download Nordic sniffer firmware (if not cached) and flash the connected nRF52840 USB Dongle. The user must plug it in first.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="start_capture",
                description=(
                    "Begin a new capture session. `source` is 'nrf_sniffer' (OTA via dongle, "
                    "default) or 'packetlogger' (Mac's own BT controller, HCI level — sees only "
                    "connections involving this Mac). Errors if one is already running."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "label": {"type": "string"},
                        "notes": {"type": "string"},
                        "device_mac": {"type": "string"},
                        "device_name": {"type": "string"},
                        "source": {"type": "string", "enum": ["nrf_sniffer", "packetlogger"], "default": "nrf_sniffer"},
                    },
                    "required": ["label"],
                },
            ),
            Tool(
                name="import_pklg",
                description=(
                    "Offline ingest of an Apple PacketLogger .pklg file at `path`. Creates a new "
                    "session with `label` and writes each HCI packet to the DB. Returns session_id "
                    "and packet_count."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute path to a .pklg file"},
                        "label": {"type": "string"},
                        "notes": {"type": "string"},
                        "device_name": {"type": "string"},
                    },
                    "required": ["path", "label"],
                },
            ),
            Tool(
                name="stop_capture",
                description="Stop the currently running capture session. Returns its packet count.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="export_driver",
                description=(
                    "Generate a standalone Python driver class for `device_name` from saved "
                    "protocol entries. Writes to `out_dir/<slug>.py` and returns the path + the code. "
                    "The driver has no bt-spy dependency — drop into any project."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "device_name": {"type": "string"},
                        "out_dir": {"type": "string", "default": "./drivers"},
                    },
                    "required": ["device_name"],
                },
            ),
            Tool(
                name="scaffold_ha_integration",
                description=(
                    "Generate a Home Assistant custom_component for `device_name` from saved "
                    "protocol entries. Writes to `out_dir/<slug>/`. Optional hints (local_name, "
                    "service_uuid, manufacturer_id) populate the manifest's bluetooth matcher; "
                    "if omitted, the manifest matches by device_name substring."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "device_name": {"type": "string"},
                        "out_dir": {"type": "string", "default": "./custom_components"},
                        "local_name": {"type": "string"},
                        "service_uuid": {"type": "string"},
                        "manufacturer_id": {"type": "integer"},
                        "manufacturer": {"type": "string"},
                        "model": {"type": "string"},
                    },
                    "required": ["device_name"],
                },
            ),
            Tool(
                name="ble_scan",
                description=(
                    "BLE-scan via the Mac's own Bluetooth adapter for `duration` seconds. Returns "
                    "nearby devices with addresses, names, RSSI, and advertised service UUIDs. "
                    "Useful for finding a target before `replay` or `ble_probe`."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {"duration": {"type": "number", "default": 5.0}},
                },
            ),
            Tool(
                name="ble_probe",
                description=(
                    "Connect to a BLE device, enumerate all GATT services + characteristics, read "
                    "every readable characteristic, and subscribe briefly to every notify-able one. "
                    "Returns the full GATT structure with values. If `record_as` is provided, also "
                    "creates a capture session with that label and writes each read/notify into "
                    "the DB as a packet, so you can diff/replay/analyze it like any other session."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string"},
                        "listen_for_notifications_ms": {"type": "integer", "default": 2000},
                        "record_as": {"type": "string", "description": "Session label; if set, writes to DB"},
                    },
                    "required": ["address"],
                },
            ),
            Tool(
                name="vocabulary",
                description=(
                    "Return the canonical protocol-entry-name → HA-platform mapping. Use this "
                    "to pick names for protocol entries that will scaffold cleanly into HA."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        try:
            result = await _dispatch(name, arguments)
        except Exception as exc:
            log.exception("MCP tool %s failed", name)
            result = {"error": str(exc)}
        return [TextContent(type="text", text=json.dumps(result, default=str))]

    return server


async def _dispatch(name: str, args: dict[str, Any]) -> Any:
    global _daemon
    conn = db.init_db()

    if name == "list_sessions":
        return db.list_sessions(conn)

    if name == "get_packets":
        rows = db.get_packets(
            conn,
            args["session_id"],
            handle=args.get("handle"),
            direction=args.get("direction"),
            pdu_type=args.get("pdu_type"),
            limit=args.get("limit", 200),
        )
        return _json_safe_packets(rows)

    if name == "diff_sessions":
        out = db.diff_sessions(conn, args["baseline_session_id"], args["candidate_session_id"])
        out["new_packets"] = _json_safe_packets(out["new_packets"])
        return out

    if name == "handle_summary":
        summaries = diffmod.handle_summary(conn, args["session_id"])
        return [s.__dict__ for s in summaries]

    if name == "infer_structure":
        rows = db.get_packets(
            conn, args["session_id"],
            handle=args["handle"],
            direction=args.get("direction"),
        )
        payloads = [bytes(r["payload"]) for r in rows if r["payload"] is not None]
        return diffmod.infer_structure(payloads)

    if name == "add_annotation":
        aid = db.add_annotation(
            conn,
            args["session_id"],
            args["packet_id_start"],
            args["packet_id_end"],
            args["label"],
            args.get("notes"),
        )
        return {"id": aid}

    if name == "upsert_protocol_entry":
        eid = db.upsert_protocol_entry(
            conn,
            device_name=args.get("device_name"),
            handle=args["handle"],
            direction=args["direction"],
            name=args["name"],
            structure=args.get("structure", []),
            decoder_py=args.get("decoder_py"),
            encoder_py=args.get("encoder_py"),
            confidence=args.get("confidence", 0.5),
            notes=args.get("notes"),
        )
        return {"id": eid}

    if name == "list_protocol_entries":
        return [dict(r) for r in conn.execute("SELECT * FROM protocol_entries ORDER BY created_at DESC")]

    if name == "replay":
        steps = [ReplayStep(**s) for s in args["steps"]]
        res = await run_replay(
            args["target"], steps,
            session_id=args.get("session_id"),
            listen_for_notifications_ms=args.get("listen_for_notifications_ms", 1000),
        )
        return {
            "target": res.target_mac,
            "status": res.status,
            "error": res.error,
            "sent": res.sent,
            "observations": [o.__dict__ for o in res.observations],
        }

    if name == "flash_dongle":
        loop = asyncio.get_running_loop()
        events: list[dict] = []

        def progress(msg: str, pct: float | None) -> None:
            events.append({"message": msg, "percent": pct})

        result = await loop.run_in_executor(None, lambda: flasher.flash(progress_cb=progress))
        return {
            "ok": result.ok,
            "message": result.message,
            "port": result.port,
            "firmware_path": str(result.firmware_path) if result.firmware_path else None,
            "extcap_path": str(result.extcap_path) if result.extcap_path else None,
            "events": events,
        }

    if name == "start_capture":
        if _daemon and _daemon._thread and _daemon._thread.is_alive():
            return {"error": "A capture is already running."}
        d = CaptureDaemon(
            label=args["label"],
            notes=args.get("notes"),
            device_mac=args.get("device_mac"),
            device_name=args.get("device_name"),
            source=args.get("source", "nrf_sniffer"),
        )
        d.start()
        _daemon = d
        for _ in range(20):
            if d.status.session_id is not None or d.status.error:
                break
            await asyncio.sleep(0.05)
        if d.status.error:
            return {"error": d.status.error}
        return {"session_id": d.status.session_id, "label": d.label}

    if name == "stop_capture":
        if not _daemon:
            return {"error": "No active capture."}
        _daemon.stop()
        s = _daemon.status
        out = {"stopped": True, "session_id": s.session_id, "packet_count": s.packet_count}
        return out

    if name == "export_driver":
        from pathlib import Path
        from ..integrations import driver as drv
        out_dir = Path(args.get("out_dir") or "./drivers")
        out_dir.mkdir(parents=True, exist_ok=True)
        slug = args["device_name"].lower().replace(" ", "_")
        path = out_dir / f"{slug}.py"
        code = drv.generate_driver_code(args["device_name"])
        path.write_text(code)
        return {"path": str(path), "bytes": len(code), "code": code}

    if name == "scaffold_ha_integration":
        from pathlib import Path
        from ..integrations import homeassistant as ha
        hints = ha.ScaffoldHints(
            local_name=args.get("local_name"),
            service_uuid=args.get("service_uuid"),
            manufacturer_id=args.get("manufacturer_id"),
            manufacturer=args.get("manufacturer", "Unknown"),
            model=args.get("model"),
        )
        out_dir = Path(args.get("out_dir") or "./custom_components")
        paths = ha.scaffold(args["device_name"], out_dir, hints)
        return {"paths": [str(p) for p in paths], "component_dir": str(out_dir / ha._slug(args["device_name"]))}

    if name == "import_pklg":
        from ..capture.daemon import import_pklg as do_import
        res = do_import(
            args["path"], args["label"],
            notes=args.get("notes"), device_name=args.get("device_name"),
        )
        return res

    if name == "ble_scan":
        from ..ble_host import scan
        results = await scan(args.get("duration", 5.0))
        return [r.__dict__ for r in results]

    if name == "ble_probe":
        from ..ble_host import probe
        res = await probe(
            args["address"],
            listen_for_notifications_ms=args.get("listen_for_notifications_ms", 2000),
            record_as=args.get("record_as"),
        )
        return {
            "address": res.address,
            "device_name": res.device_name,
            "error": res.error,
            "session_id": res.session_id,
            "characteristics": [c.__dict__ for c in res.characteristics],
        }

    if name == "vocabulary":
        from ..integrations import vocabulary as vocab
        return {
            "writes": vocab.WRITES_TO_PLATFORM,
            "reads": {k: {"platform": v[0], "role": v[1], "attrs": v[2]} for k, v in vocab.READS_TO_PLATFORM.items()},
        }

    return {"error": f"Unknown tool {name}"}


async def serve_stdio() -> None:
    server = build_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    settings.ensure_dirs()
    asyncio.run(serve_stdio())
