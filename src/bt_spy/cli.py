"""bt-spy command-line interface."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import db
from .capture import extcap
from .capture.daemon import run_blocking
from .config import settings
from .firmware import flasher

app = typer.Typer(no_args_is_help=True, add_completion=False, help="bt-spy — BLE protocol RE workstation")
console = Console()


def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@app.command()
def doctor() -> None:
    """Check the environment: dongle, sniffer script, nrfutil, DB."""
    _setup_logging()
    table = Table(title="bt-spy environment")
    table.add_column("check"); table.add_column("status"); table.add_column("detail")
    settings.ensure_dirs()
    db.init_db()
    table.add_row("data dir", "✓", str(settings.data_dir))
    table.add_row("db", "✓", str(settings.db_path))
    port = extcap.find_dongle_port()
    table.add_row("dongle", "✓" if port else "✗", port or "not detected — plug in + reset")
    nrfutil_bin = extcap.find_nrfutil_binary()
    script = extcap.find_extcap_script()
    if nrfutil_bin:
        table.add_row("nrfutil ble-sniffer", "✓", str(nrfutil_bin))
    elif script:
        table.add_row("sniffer extcap (legacy)", "✓", str(script))
    else:
        table.add_row("nrfutil ble-sniffer", "✗",
                      "install nrfutil 8.x from Nordic + `nrfutil install ble-sniffer`")
    table.add_row("nrfutil", "✓" if flasher.have_nrfutil() else "✗",
                  "found" if flasher.have_nrfutil() else "missing — `pip install nrfutil`")
    table.add_row("wireshark", "✓" if extcap.have_wireshark() else "?",
                  "found" if extcap.have_wireshark() else "absent (optional)")
    from .capture import packetlogger as pkl
    pl_cli = pkl.find_packetlogger_cli()
    pl_app = pkl.have_packetlogger_app()
    if pl_cli:
        table.add_row("PacketLogger (live)", "✓", str(pl_cli))
    elif pl_app:
        table.add_row("PacketLogger (live)", "?", "app present, CLI not — use GUI + `import-pklg`")
    else:
        table.add_row("PacketLogger (live)", "✗",
                      "install 'Additional Tools for Xcode' from developer.apple.com — see docs/packetlogger.md")
    console.print(table)


@app.command()
def flash(
    bundle: Path = typer.Option(None, "--bundle", "-b",
                                help="Path to manually-downloaded Nordic sniffer .zip. "
                                     "Use when the auto-download is blocked by Nordic's CDN."),
) -> None:
    """Flash Nordic sniffer firmware onto the connected nRF52840 USB Dongle."""
    _setup_logging()

    def progress(msg: str, pct):
        prefix = f"[{int(pct*100):>3}%]" if pct is not None else "[ ...]"
        console.log(f"{prefix} {msg}")

    result = flasher.flash(progress_cb=progress, bundle_path=bundle)
    if result.ok:
        console.print(f"[green]✓[/green] {result.message}")
        if result.extcap_path:
            console.print(f"  extcap: {result.extcap_path}")
    else:
        console.print(f"[red]✗[/red] {result.message}")
        raise typer.Exit(2)


@app.command()
def capture(
    label: str = typer.Argument(..., help="Short label for this session, e.g. 'baseline' or 'tap_power'"),
    notes: str = typer.Option("", "--notes", "-n"),
    source: str = typer.Option("nrf_sniffer", "--source", "-s",
                               help="Capture source: 'nrf_sniffer' (dongle, OTA) or 'packetlogger' (Mac's own BT, HCI)"),
) -> None:
    """Start a capture session; runs until Ctrl-C."""
    _setup_logging()
    console.print(f"[bold]Capturing[/bold] — label={label!r} source={source}. Press Ctrl-C to stop.")
    status = run_blocking(label, notes=notes or None, source=source)
    console.print(f"\nDone. session_id={status.session_id} packets={status.packet_count}")
    if status.error:
        console.print(f"[red]error:[/red] {status.error}")
        raise typer.Exit(2)


@app.command()
def scan(
    duration: float = typer.Option(5.0, "--duration", "-d", help="Scan duration in seconds"),
) -> None:
    """BLE-scan via the Mac's own Bluetooth — list nearby devices.

    Great pairing with PacketLogger: open PacketLogger.app and hit record,
    then run this. Every advertisement you see in the table will also show
    up in the .pklg file you save afterwards.
    """
    from .ble_host import scan_sync
    results = scan_sync(duration)
    if not results:
        console.print("[dim]No BLE devices found in scan window.[/dim]")
        return
    t = Table(title=f"BLE scan ({duration}s) — {len(results)} device(s)")
    t.add_column("address"); t.add_column("name"); t.add_column("rssi"); t.add_column("services")
    for r in results:
        t.add_row(r.address, r.name or "", str(r.rssi or ""), ", ".join(r.service_uuids[:3]))
    console.print(t)


@app.command()
def probe(
    address: str = typer.Argument(..., help="BLE address or CoreBluetooth UUID"),
    listen_ms: int = typer.Option(2000, "--listen-ms"),
    record_as: str = typer.Option(None, "--record-as", "-r",
                                  help="Also record this probe as a bt-spy session with this label"),
) -> None:
    """Connect to a BLE device, enumerate GATT, read every readable characteristic,
    subscribe briefly to every notify-able one.

    With --record-as LABEL, also creates a bt-spy capture session and writes each
    read/notify as a packet — the easiest way to see a real session in bt-spy
    without PacketLogger.app or the dongle.
    """
    from .ble_host import probe_sync
    res = probe_sync(address, listen_for_notifications_ms=listen_ms, record_as=record_as)
    if res.error:
        console.print(f"[red]✗[/red] {res.error}")
        raise typer.Exit(2)
    if res.session_id is not None:
        console.print(f"[green]✓[/green] recorded as session #{res.session_id}")
    t = Table(title=f"GATT on {address} — {len(res.characteristics)} characteristic(s)")
    t.add_column("service"); t.add_column("char"); t.add_column("h"); t.add_column("props"); t.add_column("read"); t.add_column("notifies")
    for c in res.characteristics:
        notif = "—" if not c.notify_received_hex else f"{len(c.notify_received_hex)} msg"
        read = c.read_value_hex or (c.read_error and f"err:{c.read_error[:20]}") or "—"
        t.add_row(
            c.service_uuid[:8], c.char_uuid[:8], str(c.handle or ""),
            ",".join(c.properties), read[:24], notif,
        )
    console.print(t)


@app.command("import-pklg")
def import_pklg_cmd(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                help=".pklg file saved from Apple's PacketLogger.app"),
    label: str = typer.Option(..., "--label", "-l", help="Label this session, e.g. 'mac_drives_bulb'"),
    notes: str = typer.Option("", "--notes", "-n"),
    device_name: str = typer.Option(None, "--device-name"),
) -> None:
    """Offline ingest a .pklg file as a capture session.

    Use this when you've captured HCI traffic on the Mac via PacketLogger.app
    and want to analyse/diff/replay it inside bt-spy. No dongle needed.
    """
    _setup_logging()
    from .capture.daemon import import_pklg
    res = import_pklg(file, label, notes=notes or None, device_name=device_name)
    console.print(f"[green]✓[/green] session_id={res['session_id']} packets={res['packet_count']}")


@app.command()
def sessions() -> None:
    """List all capture sessions."""
    conn = db.init_db()
    rows = db.list_sessions(conn)
    if not rows:
        console.print("[dim]No sessions yet.[/dim]")
        return
    t = Table(title="sessions")
    t.add_column("id"); t.add_column("label"); t.add_column("packets"); t.add_column("started"); t.add_column("ended")
    for s in rows:
        n = conn.execute("SELECT COUNT(*) FROM packets WHERE session_id=?", (s["id"],)).fetchone()[0]
        t.add_row(
            str(s["id"]), s["label"], str(n),
            _ts(s["started_at"]),
            _ts(s["ended_at"]) if s["ended_at"] else "[yellow]active[/yellow]",
        )
    console.print(t)


@app.command()
def export(
    session_id: int,
    out: Path = typer.Option(Path("session.jsonl"), "--out", "-o"),
) -> None:
    """Export a session to JSON Lines (raw bytes hex-encoded). Handy for handing to Claude."""
    conn = db.init_db()
    with out.open("w") as f:
        for line in db.export_session_jsonl(conn, session_id):
            f.write(line + "\n")
    console.print(f"[green]✓[/green] wrote {out}")


@app.command()
def diff(baseline: int, candidate: int) -> None:
    """Print packets in `candidate` that didn't appear in `baseline`."""
    conn = db.init_db()
    res = db.diff_sessions(conn, baseline, candidate)
    console.print(f"[bold]{res['new_packet_count']}[/bold] new packets")
    for p in res["new_packets"][:50]:
        payload = bytes(p["payload"]).hex() if p["payload"] else ""
        console.print(f"  id={p['id']:<5} t={p['ts']:.3f} {p['direction'] or '?'} h={p['handle']} {p['pdu_type'] or ''} {payload}")
    if res["new_packet_count"] > 50:
        console.print(f"[dim]… and {res['new_packet_count']-50} more[/dim]")


@app.command()
def replay(
    target: str = typer.Argument(..., help="Device name or CoreBluetooth UUID"),
    steps_json: str = typer.Argument(..., help="JSON list of replay steps; see docs/user-guide.md"),
    session_id: int = typer.Option(None, "--session-id"),
) -> None:
    """Run a replay sequence against a live device."""
    from .replay.engine import ReplayStep, run_replay
    steps = [ReplayStep(**s) for s in json.loads(steps_json)]
    res = asyncio.run(run_replay(target, steps, session_id=session_id))
    console.print_json(json.dumps({
        "target": res.target_mac,
        "status": res.status,
        "error": res.error,
        "sent": res.sent,
        "observations": [o.__dict__ for o in res.observations],
    }))


@app.command()
def serve(
    host: str = typer.Option(None, "--host"),
    port: int = typer.Option(None, "--port"),
) -> None:
    """Run the REST + WebSocket + Web UI server (default http://127.0.0.1:8765)."""
    _setup_logging()
    from .api.server import run as run_api
    run_api(host=host, port=port)


@app.command()
def mcp() -> None:
    """Run the MCP server (stdio). Add this to your Claude Code config."""
    _setup_logging("WARNING")  # MCP stdio expects clean stdout; keep logs quiet.
    from .mcp.server import main as mcp_main
    mcp_main()


@app.command("export-driver")
def export_driver_cmd(
    device_name: str = typer.Argument(..., help="The device_name used in your protocol entries"),
    out: Path = typer.Option(Path("drivers"), "--out", "-o", help="Output directory"),
) -> None:
    """Emit a standalone Python driver class for a device. No HA dependency."""
    from .integrations import driver as drv
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{drv._slug_module(device_name) if hasattr(drv, '_slug_module') else device_name.lower().replace(' ', '_')}.py"
    drv.write_driver(device_name, path)
    console.print(f"[green]✓[/green] wrote {path}")


@app.command("scaffold-ha")
def scaffold_ha_cmd(
    device_name: str = typer.Argument(..., help="The device_name used in your protocol entries"),
    out: Path = typer.Option(Path("custom_components"), "--out", "-o", help="Parent of the generated custom_components dir"),
    local_name: str = typer.Option(None, "--local-name", help="BLE advertised name for HA discovery matcher"),
    service_uuid: str = typer.Option(None, "--service-uuid", help="Primary service UUID for HA discovery matcher"),
    manufacturer_id: int = typer.Option(None, "--manufacturer-id", help="BLE manufacturer ID for HA discovery matcher"),
) -> None:
    """Generate a complete custom_components/<device>/ directory for Home Assistant."""
    from .integrations import homeassistant as ha
    hints = ha.ScaffoldHints(
        local_name=local_name, service_uuid=service_uuid, manufacturer_id=manufacturer_id,
    )
    paths = ha.scaffold(device_name, out, hints)
    console.print(f"[green]✓[/green] scaffolded {len(paths)} files under {out / ha._slug(device_name)}")
    for p in paths:
        console.print(f"  {p}")


@app.command("bridge")
def bridge_cmd(
    device_name: str = typer.Option(..., "--device", help="Device with saved protocol entries"),
    ble_address: str = typer.Option(..., "--ble", help="BLE address / CoreBluetooth UUID of the device"),
    mqtt: str = typer.Option(..., "--mqtt", help="mqtt://[user:pass@]host[:port]"),
    base_topic: str = typer.Option(None, "--base-topic"),
) -> None:
    """Run as a long-lived MQTT bridge exposing the device to HA via MQTT discovery."""
    from .integrations.mqtt_bridge import BridgeConfig, run_blocking
    cfg = BridgeConfig(
        device_name=device_name, ble_address=ble_address, mqtt_url=mqtt, base_topic=base_topic,
    )
    console.print(f"[bold]Bridging[/bold] {device_name} ↔ {mqtt}. Ctrl-C to stop.")
    try:
        run_blocking(cfg)
    except KeyboardInterrupt:
        console.print("\nstopped")


def _ts(t: float | None) -> str:
    import datetime as dt
    if not t:
        return ""
    return dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    app()
