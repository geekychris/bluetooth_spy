"""FastAPI app: REST + WebSocket + static UI.

Run with `bt-spy serve` or directly: `uvicorn bt_spy.api.server:app --reload`.

Routes:
  GET  /                          → web UI
  GET  /api/health                → quick liveness + dongle state
  GET  /api/sessions              → list capture sessions
  POST /api/sessions              → start a new capture session  body: {label, notes?}
  POST /api/sessions/{id}/stop    → stop the running capture
  GET  /api/sessions/{id}/packets → query packets (?handle=&direction=&pdu_type=&limit=)
  POST /api/annotations           → add annotation
  POST /api/diff                  → diff two sessions  body: {baseline, candidate}
  GET  /api/handle_summary/{id}   → handle activity summary
  POST /api/replay                → run a replay      body: {target, steps[], session_id?}
  POST /api/flash                 → flash the dongle (SSE-streamed progress)
  POST /api/protocol_entries      → upsert a protocol entry
  GET  /api/protocol_entries      → list entries
  WS   /ws/packets                → live packet broadcast for active session
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from .. import db
from ..capture import extcap
from ..capture.daemon import CaptureDaemon
from ..config import settings
from ..firmware import flasher
from ..replay.engine import ReplayStep, run_replay

log = logging.getLogger(__name__)

PKG_ROOT = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(PKG_ROOT / "web" / "templates"))

app = FastAPI(title="bt-spy", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(PKG_ROOT / "web" / "static")), name="static")


# ---------- shared state ----------

class AppState:
    def __init__(self) -> None:
        self.daemon: CaptureDaemon | None = None
        self.ws_clients: set[WebSocket] = set()
        self.event_loop: asyncio.AbstractEventLoop | None = None


state = AppState()


@app.on_event("startup")
async def _startup() -> None:
    state.event_loop = asyncio.get_running_loop()
    settings.ensure_dirs()
    db.init_db()


def _broadcast(event: dict) -> None:
    """Called from the capture thread; schedule WS sends on the FastAPI loop."""
    loop = state.event_loop
    if loop is None or not state.ws_clients:
        return
    text = json.dumps(event)

    async def _send_all() -> None:
        dead: list[WebSocket] = []
        for ws in list(state.ws_clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            state.ws_clients.discard(ws)

    asyncio.run_coroutine_threadsafe(_send_all(), loop)


# ---------- models ----------

class StartCapture(BaseModel):
    label: str
    notes: str | None = None
    device_mac: str | None = None
    device_name: str | None = None
    source: str = "nrf_sniffer"  # 'nrf_sniffer' | 'packetlogger' | 'pklg_tail'
    source_args: dict | None = None  # e.g., {"path": "/Users/me/captures/live.pklg"} for pklg_tail
    device_filter: list[str] | None = None  # allow-list: BD_ADDRs OR alias names; None = no filter


class DiffRequest(BaseModel):
    baseline: int
    candidate: int


class ReplayStepModel(BaseModel):
    handle: int | None = None
    char_uuid: str | None = None
    payload_hex: str = ""
    delay_before_ms: int = 0
    write_with_response: bool = True
    mutation: dict[str, Any] | None = None


class ReplayRequest(BaseModel):
    target: str
    steps: list[ReplayStepModel]
    session_id: int | None = None
    listen_for_notifications_ms: int = 1000


class AnnotationRequest(BaseModel):
    session_id: int
    packet_id_start: int
    packet_id_end: int
    label: str
    notes: str | None = None


class ProtocolEntryRequest(BaseModel):
    device_name: str | None = None
    handle: int
    direction: str
    name: str
    structure: list[dict[str, Any]] = []
    decoder_py: str | None = None
    encoder_py: str | None = None
    confidence: float = 0.5
    notes: str | None = None


# ---------- routes ----------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> Any:
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/health")
async def health() -> dict:
    from ..capture import packetlogger as pkl
    conn = db.init_db()
    pl_cli = pkl.find_packetlogger_cli()
    nrfutil_bin = extcap.find_nrfutil_binary()
    return {
        "ok": True,
        "version": "0.1.0",
        "db": str(settings.db_path),
        "extcap_script": str(extcap.find_extcap_script() or ""),
        "nrfutil_binary": str(nrfutil_bin) if nrfutil_bin else None,
        "dongle_port": extcap.find_dongle_port(),
        "wireshark_present": extcap.have_wireshark(),
        "nrfutil_present": flasher.have_nrfutil(),
        "packetlogger_cli": str(pl_cli) if pl_cli else None,
        "packetlogger_app_present": pkl.have_packetlogger_app(),
        "capture_running": bool(state.daemon and state.daemon._thread and state.daemon._thread.is_alive()),
        "capture_status": state.daemon.status.__dict__ if state.daemon else None,
        "sessions_total": conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
    }


@app.get("/api/ble/scan")
async def api_ble_scan(duration: float = 5.0) -> list[dict]:
    from ..ble_host import scan
    results = await scan(duration)
    return [r.__dict__ for r in results]


@app.post("/api/ble/probe")
async def api_ble_probe(payload: dict) -> dict:
    """body: {address, listen_for_notifications_ms?, record_as?}

    If a capture is currently running AND we know a friendly name for the probed
    address (typically a CoreBluetooth UUID with a `scan`-sourced alias), we
    watch the daemon's connection-complete log to bridge UUID ↔ MAC: any new MAC
    learned during the probe window gets the same name auto-assigned. Solves the
    macOS hidden-MAC problem for one probe per device.
    """
    import time as _time
    from ..ble_host import probe

    addr_to_probe = payload["address"]
    sub = _broadcast if payload.get("record_as") else None

    # Snapshot for bridging
    conn = db.init_db()
    pre_aliases = db.get_device_aliases(conn)
    target_name = pre_aliases.get(addr_to_probe)
    bridge_start = _time.time()

    res = await probe(
        addr_to_probe,
        listen_for_notifications_ms=payload.get("listen_for_notifications_ms", 2000),
        record_as=payload.get("record_as"),
        subscriber=sub,
    )

    # Bridging: if a capture is running and we have a name for the probed addr,
    # check what MACs the daemon saw during the probe window.
    bridged: list[dict] = []
    daemon = state.daemon
    if daemon and target_name:
        learnings = daemon.recent_address_learnings(bridge_start)
        # Candidate MACs = ones not already aliased and not equal to the probed address.
        seen_macs = {l["device_addr"] for l in learnings}
        candidates = [m for m in seen_macs if m not in pre_aliases and m != addr_to_probe]
        if len(candidates) == 1:
            mac = candidates[0]
            db.upsert_device_alias(conn, mac, target_name, source="probe-bridge")
            bridged.append({"mac": mac, "name": target_name, "from_address": addr_to_probe})
        elif len(candidates) > 1:
            # Don't guess — record the candidates so the UI can show them.
            bridged.append({"ambiguous_macs": candidates, "name": target_name})

    return {
        "address": res.address,
        "device_name": res.device_name,
        "error": res.error,
        "session_id": res.session_id,
        "characteristics": [c.__dict__ for c in res.characteristics],
        "bridged_aliases": bridged,
    }


@app.get("/api/pklg/detect")
async def detect_live_pklg() -> dict:
    """Tell the UI which .pklg file PL.app is actively writing to, if any.

    Lets the Capture form auto-fill the pklg_tail path field so users don't
    have to find and paste it themselves.
    """
    from ..capture import packetlogger as pkl
    p = pkl.find_live_pklg_file()
    if not p:
        return {"path": None, "reason": "PacketLogger.app not running, or not saving live."}
    try:
        st = p.stat()
        size = st.st_size
        mtime = st.st_mtime
    except FileNotFoundError:
        return {"path": None, "reason": "Detected file no longer exists."}
    return {"path": str(p), "size": size, "mtime": mtime}


@app.get("/api/sessions/{sid}/export.pcap")
async def export_pcap(sid: int):
    """Stream the session as a .pcap file. Wireshark can open it natively."""
    import io
    from .. import export_pcap
    conn = db.init_db()
    buf = io.BytesIO()
    n = export_pcap.write_pcap(conn, sid, buf)
    if n == 0:
        raise HTTPException(404, "no packets in session")
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="session_{sid}.pcap"'},
    )


@app.post("/api/import_pklg")
async def import_pklg_endpoint(
    file: UploadFile = File(...),
    label: str = Form(...),
    notes: str | None = Form(None),
    device_name: str | None = Form(None),
) -> dict:
    """Upload a .pklg file and ingest as a new capture session."""
    from ..capture.daemon import import_pklg as do_import
    settings.ensure_dirs()
    # Persist upload to the data dir so we can replay/inspect later if needed.
    target = settings.data_dir / "uploads"
    target.mkdir(parents=True, exist_ok=True)
    dest = target / file.filename
    contents = await file.read()
    dest.write_bytes(contents)
    res = do_import(dest, label, notes=notes, device_name=device_name)
    return {"uploaded_to": str(dest), **res}


@app.get("/api/sessions")
async def list_sessions() -> list[dict]:
    conn = db.init_db()
    return db.list_sessions(conn)


@app.post("/api/sessions")
async def start_session(req: StartCapture) -> dict:
    if state.daemon and state.daemon._thread and state.daemon._thread.is_alive():
        raise HTTPException(409, "A capture is already running. Stop it first.")
    # Resolve any alias names in device_filter to BD_ADDRs via the alias DB.
    resolved_filter: list[str] | None = None
    if req.device_filter:
        conn = db.init_db()
        # Map name → list of addresses (a name may be attached to multiple addrs)
        name_to_addrs: dict[str, list[str]] = {}
        for r in conn.execute("SELECT device_addr, name FROM device_aliases"):
            name_to_addrs.setdefault(r["name"], []).append(r["device_addr"])
        resolved: list[str] = []
        for item in req.device_filter:
            item = item.strip()
            if not item:
                continue
            if ":" in item or "-" in item:
                # Looks like an address (BD_ADDR or CB UUID) — keep as-is.
                resolved.append(item)
            elif item in name_to_addrs:
                resolved.extend(name_to_addrs[item])
            else:
                # Unknown — let it through. If user mistyped, no packets match → no harm done.
                resolved.append(item)
        resolved_filter = sorted(set(resolved)) if resolved else None

    d = CaptureDaemon(
        label=req.label, notes=req.notes,
        device_mac=req.device_mac, device_name=req.device_name,
        source=req.source, source_args=req.source_args,
        device_filter=resolved_filter,
    )
    d.add_subscriber(_broadcast)
    d.start()
    state.daemon = d
    # Wait briefly for the session row to be created
    for _ in range(20):
        if d.status.session_id is not None or d.status.error:
            break
        await asyncio.sleep(0.05)
    if d.status.error:
        raise HTTPException(500, d.status.error)
    return {
        "session_id": d.status.session_id,
        "label": d.label,
        "device_filter": resolved_filter,
    }


@app.post("/api/sessions/{sid}/stop")
async def stop_session(sid: int) -> dict:
    if not state.daemon:
        raise HTTPException(404, "No active capture")
    state.daemon.stop()
    s = state.daemon.status
    state.daemon = None
    return {"stopped": True, "session_id": s.session_id, "packet_count": s.packet_count}


@app.get("/api/sessions/{sid}/packets")
async def get_packets(
    sid: int,
    handle: int | None = None,
    direction: str | None = None,
    pdu_type: str | None = None,
    device_addr: str | None = None,
    device_name: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """`device_addr` filters by exact BD_ADDR/UUID. `device_name` resolves through
    the alias DB to every address registered under that name (handles privacy
    address rotation: same name → many addresses → union filter)."""
    conn = db.init_db()
    addr_filter: str | list[str] | None = device_addr
    if device_name:
        addrs_from_name = db.addrs_for_alias_name(conn, device_name)
        if device_addr:
            addr_filter = list({device_addr, *addrs_from_name})
        else:
            addr_filter = addrs_from_name or [device_name]  # fallback: filter by literal if no alias matches
    rows = db.get_packets(conn, sid, handle=handle, direction=direction,
                          pdu_type=pdu_type, device_addr=addr_filter, limit=limit)
    for r in rows:
        if r.get("payload") is not None:
            r["payload_hex"] = bytes(r["payload"]).hex()
            r.pop("payload", None)
        if r.get("raw") is not None:
            r["raw_hex"] = bytes(r["raw"]).hex()
            r.pop("raw", None)
    return rows


@app.post("/api/annotations")
async def add_annotation(req: AnnotationRequest) -> dict:
    conn = db.init_db()
    aid = db.add_annotation(
        conn, req.session_id, req.packet_id_start, req.packet_id_end, req.label, req.notes
    )
    return {"id": aid}


class MarkerRequest(BaseModel):
    session_id: int
    label: str
    notes: str | None = None


@app.post("/api/marker")
async def add_marker(req: MarkerRequest) -> dict:
    """Mark the current capture frontier with a label.

    Creates an annotation spanning from the last marker's end (or session start)
    to the most recent packet. Useful for tagging what you were doing in real
    time during capture ("tap_power_on", "slid_brightness", etc.).
    """
    conn = db.init_db()
    latest = db.latest_packet_id(conn, req.session_id) or 0
    # Where does this marker start? End-of-previous-marker + 1, or session start.
    rows = list(conn.execute(
        "SELECT packet_id_end FROM annotations WHERE session_id=? ORDER BY packet_id_end DESC LIMIT 1",
        (req.session_id,),
    ))
    start = (rows[0]["packet_id_end"] + 1) if rows else 1
    # Clamp end if no packets yet
    end = max(latest, start)
    aid = db.add_annotation(conn, req.session_id, start, end, req.label, req.notes)
    return {"id": aid, "packet_id_start": start, "packet_id_end": end, "label": req.label}


@app.get("/api/sessions/{sid}/annotations")
async def session_annotations(sid: int) -> list[dict]:
    return db.get_annotations(db.init_db(), sid)


@app.get("/api/annotations/{aid}/packets")
async def packets_in_annotation(aid: int, limit: int = 500) -> dict:
    """Return all packets covered by a single annotation (marker range)."""
    conn = db.init_db()
    ann = conn.execute("SELECT * FROM annotations WHERE id=?", (aid,)).fetchone()
    if not ann:
        raise HTTPException(404, "annotation not found")
    rows = conn.execute(
        "SELECT * FROM packets WHERE session_id=? AND id BETWEEN ? AND ? ORDER BY ts ASC LIMIT ?",
        (ann["session_id"], ann["packet_id_start"], ann["packet_id_end"], limit),
    ).fetchall()
    packets = []
    for r in rows:
        d = dict(r)
        if d.get("payload") is not None:
            d["payload_hex"] = bytes(d["payload"]).hex()
            d.pop("payload", None)
        if d.get("raw") is not None:
            d["raw_hex"] = bytes(d["raw"]).hex()
            d.pop("raw", None)
        packets.append(d)
    return {"annotation": dict(ann), "packets": packets, "packet_count": len(rows)}


class MarkerDiffRequest(BaseModel):
    baseline_annotation_id: int
    candidate_annotation_id: int


@app.post("/api/marker_diff")
async def marker_diff(req: MarkerDiffRequest) -> dict:
    """Diff two marker ranges. Returns packets in `candidate` whose (handle, dir, payload)
    didn't appear in `baseline`. Like diff_sessions but within ranges of one session."""
    conn = db.init_db()
    base = conn.execute("SELECT * FROM annotations WHERE id=?", (req.baseline_annotation_id,)).fetchone()
    cand = conn.execute("SELECT * FROM annotations WHERE id=?", (req.candidate_annotation_id,)).fetchone()
    if not base or not cand:
        raise HTTPException(404, "annotation(s) not found")

    def fingerprints(start, end):
        return {
            (r["handle"], r["direction"], bytes(r["payload"]) if r["payload"] else None)
            for r in conn.execute(
                "SELECT handle, direction, payload FROM packets WHERE id BETWEEN ? AND ?",
                (start, end),
            )
        }

    base_fps = fingerprints(base["packet_id_start"], base["packet_id_end"])
    cand_rows = list(conn.execute(
        "SELECT * FROM packets WHERE id BETWEEN ? AND ? ORDER BY ts ASC",
        (cand["packet_id_start"], cand["packet_id_end"]),
    ))
    new_packets = []
    for r in cand_rows:
        key = (r["handle"], r["direction"], bytes(r["payload"]) if r["payload"] else None)
        if key not in base_fps:
            d = dict(r)
            if d.get("payload") is not None:
                d["payload_hex"] = bytes(d["payload"]).hex()
                d.pop("payload", None)
            d.pop("raw", None)
            new_packets.append(d)
    return {
        "baseline": dict(base),
        "candidate": dict(cand),
        "new_packet_count": len(new_packets),
        "new_packets": new_packets,
    }


@app.get("/api/sessions/{sid}/conn_handles")
async def session_conn_handles(sid: int) -> list[dict]:
    return db.conn_handles_in_session(db.init_db(), sid)


@app.get("/api/sessions/{sid}/devices")
async def session_devices(sid: int) -> list[dict]:
    """Distinct BD_ADDRs seen in this session, with packet counts. Use to populate
    a device filter — pick a row to filter the session view down to one device."""
    return db.devices_in_session(db.init_db(), sid)


class DeviceAliasRequest(BaseModel):
    device_addr: str
    name: str
    source: str = "user"


@app.post("/api/device_alias")
async def set_device_alias(req: DeviceAliasRequest) -> dict:
    """Attach a friendly name to a BD_ADDR (or CoreBluetooth UUID). Survives across
    captures — once you've named a device, future captures show the name automatically."""
    conn = db.init_db()
    if not req.name.strip():
        conn.execute("DELETE FROM device_aliases WHERE device_addr=?", (req.device_addr,))
        return {"deleted": req.device_addr}
    db.upsert_device_alias(conn, req.device_addr, req.name.strip(), source=req.source)
    return {"device_addr": req.device_addr, "name": req.name.strip(), "source": req.source}


@app.delete("/api/device_alias/{addr}")
async def delete_device_alias(addr: str) -> dict:
    conn = db.init_db()
    conn.execute("DELETE FROM device_aliases WHERE device_addr=?", (addr,))
    return {"deleted": addr}


@app.get("/api/device_aliases")
async def list_device_aliases() -> list[dict]:
    return [dict(r) for r in db.init_db().execute(
        "SELECT * FROM device_aliases ORDER BY last_seen DESC"
    )]


class LTKRequest(BaseModel):
    device_addr: str
    ltk_hex: str
    rand_hex: str | None = None
    ediv: int | None = None
    notes: str | None = None


@app.post("/api/ltk")
async def set_ltk(req: LTKRequest) -> dict:
    """Attach a long-term key to a device address. Future captures will attempt
    AES-CCM decryption of that device's encrypted ACL packets using this key."""
    conn = db.init_db()
    if not req.ltk_hex.strip():
        conn.execute("DELETE FROM device_ltks WHERE device_addr=?", (req.device_addr,))
        return {"deleted": req.device_addr}
    db.upsert_ltk(conn, req.device_addr, req.ltk_hex.strip().replace(" ", ""),
                  rand_hex=req.rand_hex, ediv=req.ediv, notes=req.notes)
    return {"device_addr": req.device_addr}


@app.get("/api/ltks")
async def list_ltks() -> list[dict]:
    rows = db.init_db().execute("SELECT * FROM device_ltks ORDER BY created_at DESC")
    # Don't leak full LTKs to the UI in plaintext — show first/last 4 chars only.
    return [
        {**dict(r), "ltk_hex": (dict(r)["ltk_hex"][:4] + "…" + dict(r)["ltk_hex"][-4:])
         if dict(r)["ltk_hex"] else ""}
        for r in rows
    ]


@app.get("/api/packets/{pid}")
async def get_packet_detail(pid: int) -> dict:
    conn = db.init_db()
    row = db.get_packet(conn, pid)
    if not row:
        raise HTTPException(404, "packet not found")
    if row.get("payload") is not None:
        row["payload_hex"] = bytes(row["payload"]).hex()
        row.pop("payload", None)
    if row.get("raw") is not None:
        row["raw_hex"] = bytes(row["raw"]).hex()
        row.pop("raw", None)
    # The decoded blob is JSON-encoded text in the DB; parse for the UI.
    if row.get("decoded"):
        try:
            row["decoded"] = json.loads(row["decoded"])
        except Exception:
            pass
    return row


@app.post("/api/diff")
async def diff(req: DiffRequest) -> dict:
    conn = db.init_db()
    out = db.diff_sessions(conn, req.baseline, req.candidate)
    for r in out["new_packets"]:
        if r.get("payload") is not None:
            r["payload_hex"] = bytes(r["payload"]).hex()
            r.pop("payload", None)
        if r.get("raw") is not None:
            r["raw_hex"] = bytes(r["raw"]).hex()
            r.pop("raw", None)
    return out


@app.get("/api/handle_summary/{sid}")
async def handle_summary(sid: int) -> list[dict]:
    from ..analysis import diff as diffmod
    conn = db.init_db()
    summaries = diffmod.handle_summary(conn, sid)
    return [s.__dict__ for s in summaries]


@app.get("/api/checksum_hypotheses/{sid}")
async def checksum_hypotheses(
    sid: int, handle: int | None = None, direction: str | None = None,
) -> list[dict]:
    """Brute-force checksum detection over payloads of a (session, handle, direction).

    Returns ranked hypotheses: each names an algorithm (sum8, crc16_modbus, …),
    the input byte range, and which byte(s) hold the checksum. Useful for the
    "is byte 3 a CRC?" question that comes up every RE session.
    """
    from ..analysis import checksum
    conn = db.init_db()
    rows = db.get_packets(conn, sid, handle=handle, direction=direction)
    payloads = [bytes(r["payload"]) for r in rows if r["payload"] is not None]
    return [h.__dict__ for h in checksum.find_checksums(payloads)]


class SweepReplayRequest(BaseModel):
    target: str
    char_uuid: str
    base_payload_hex: str
    offset: int
    value_start: int = 0
    value_end: int = 255
    step: int = 1
    delay_ms: int = 200
    listen_ms_per_step: int = 0
    write_with_response: bool = False
    session_id: int | None = None


@app.post("/api/replay/sweep")
async def replay_sweep(req: SweepReplayRequest) -> dict:
    from ..replay.engine import SweepRequest, run_sweep
    res = await run_sweep(SweepRequest(**req.model_dump(exclude={"session_id"})), session_id=req.session_id)
    return {
        "target": res.target_mac,
        "status": res.status,
        "error": res.error,
        "sent_count": len(res.sent),
        "observations": [o.__dict__ for o in res.observations],
    }


@app.post("/api/replay")
async def replay(req: ReplayRequest) -> dict:
    steps = [ReplayStep(**s.model_dump()) for s in req.steps]
    res = await run_replay(
        req.target, steps,
        session_id=req.session_id,
        listen_for_notifications_ms=req.listen_for_notifications_ms,
    )
    return {
        "target": res.target_mac,
        "status": res.status,
        "error": res.error,
        "sent": res.sent,
        "observations": [o.__dict__ for o in res.observations],
    }


@app.post("/api/protocol_entries")
async def upsert_protocol_entry(req: ProtocolEntryRequest) -> dict:
    conn = db.init_db()
    eid = db.upsert_protocol_entry(
        conn,
        device_name=req.device_name,
        handle=req.handle,
        direction=req.direction,
        name=req.name,
        structure=req.structure,
        decoder_py=req.decoder_py,
        encoder_py=req.encoder_py,
        confidence=req.confidence,
        notes=req.notes,
    )
    return {"id": eid}


@app.get("/api/protocol_entries")
async def list_protocol_entries() -> list[dict]:
    conn = db.init_db()
    return [dict(r) for r in conn.execute("SELECT * FROM protocol_entries ORDER BY created_at DESC")]


class ExportDriverRequest(BaseModel):
    device_name: str
    out_dir: str = "./drivers"


class ScaffoldHARequest(BaseModel):
    device_name: str
    out_dir: str = "./custom_components"
    local_name: str | None = None
    service_uuid: str | None = None
    manufacturer_id: int | None = None
    manufacturer: str = "Unknown"
    model: str | None = None


@app.post("/api/integrations/export_driver")
async def api_export_driver(req: ExportDriverRequest) -> dict:
    from pathlib import Path
    from ..integrations import driver as drv
    out_dir = Path(req.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{req.device_name.lower().replace(' ', '_')}.py"
    code = drv.generate_driver_code(req.device_name)
    path.write_text(code)
    return {"path": str(path), "bytes": len(code), "code": code}


@app.post("/api/integrations/scaffold_ha")
async def api_scaffold_ha(req: ScaffoldHARequest) -> dict:
    from pathlib import Path
    from ..integrations import homeassistant as ha
    hints = ha.ScaffoldHints(
        local_name=req.local_name, service_uuid=req.service_uuid,
        manufacturer_id=req.manufacturer_id, manufacturer=req.manufacturer, model=req.model,
    )
    out_dir = Path(req.out_dir)
    paths = ha.scaffold(req.device_name, out_dir, hints)
    return {"paths": [str(p) for p in paths], "component_dir": str(out_dir / ha._slug(req.device_name))}


@app.get("/api/integrations/vocabulary")
async def api_vocabulary() -> dict:
    from ..integrations import vocabulary as vocab
    return {
        "writes": vocab.WRITES_TO_PLATFORM,
        "reads": {k: {"platform": v[0], "role": v[1], "attrs": v[2]} for k, v in vocab.READS_TO_PLATFORM.items()},
    }


@app.get("/api/integrations/devices")
async def api_devices() -> list[dict]:
    """Devices known to have protocol entries (the targets you can export / scaffold for)."""
    conn = db.init_db()
    rows = conn.execute(
        "SELECT device_name, COUNT(*) AS entries FROM protocol_entries "
        "WHERE device_name IS NOT NULL GROUP BY device_name ORDER BY entries DESC"
    )
    return [dict(r) for r in rows]


@app.post("/api/flash/upload")
async def flash_from_uploaded_bundle(file: UploadFile = File(...)) -> dict:
    """Upload a manually-downloaded sniffer bundle .zip and flash with it.

    Same as POST /api/flash but skips the auto-download. Use when Nordic's CDN
    is blocking direct download.
    """
    settings.ensure_dirs()
    dest = settings.firmware_cache_dir / "uploaded_sniffer_bundle.zip"
    contents = await file.read()
    dest.write_bytes(contents)
    loop = asyncio.get_running_loop()
    events: list[dict] = []

    def progress(msg, pct):
        events.append({"message": msg, "percent": pct})

    result = await loop.run_in_executor(
        None, lambda: flasher.flash(progress_cb=progress, bundle_path=dest)
    )
    return {
        "ok": result.ok,
        "message": result.message,
        "port": result.port,
        "events": events,
    }


@app.post("/api/flash")
async def flash_dongle() -> StreamingResponse:
    """Stream flashing progress as Server-Sent Events.

    UI listens via EventSource. Each event is JSON: {message, percent|null, done}.
    """

    queue: asyncio.Queue = asyncio.Queue()

    def progress(msg: str, pct: float | None) -> None:
        # Called from worker thread; schedule onto loop
        loop = state.event_loop
        if loop:
            loop.call_soon_threadsafe(queue.put_nowait, {"message": msg, "percent": pct, "done": False})

    async def runner() -> None:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: flasher.flash(progress_cb=progress))
        await queue.put({"message": result.message, "percent": 1.0 if result.ok else None, "done": True, "ok": result.ok})

    asyncio.create_task(runner())

    async def gen():
        while True:
            ev = await queue.get()
            yield f"data: {json.dumps(ev)}\n\n"
            if ev.get("done"):
                return

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.websocket("/ws/packets")
async def ws_packets(ws: WebSocket) -> None:
    await ws.accept()
    state.ws_clients.add(ws)
    try:
        while True:
            # We don't expect client→server traffic; this keeps the connection open.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        state.ws_clients.discard(ws)


def run(host: str | None = None, port: int | None = None) -> None:
    import uvicorn
    uvicorn.run(
        "bt_spy.api.server:app",
        host=host or settings.rest_host,
        port=port or settings.rest_port,
        reload=False,
    )
