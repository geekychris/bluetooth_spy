"""Replay observed BLE writes against a real device, with mutation support.

Why this matters for RE: capture tells you *what the app sent*; replay tells you
*what the device does when it receives a payload*. To confirm "byte 2 is brightness,"
you mutate that byte and see if behaviour matches. This module is the bottom half
of that loop — the Python side that drives bleak.

Mutation strategies are pluggable. Register a callable like:

    @register_mutation("set_byte")
    def set_byte(payload: bytes, *, offset: int, value: int) -> bytes: ...

The replay engine resolves the strategy by name from the request JSON.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .. import db
from ..config import settings

log = logging.getLogger(__name__)

MutationFn = Callable[..., bytes]
_MUTATIONS: dict[str, MutationFn] = {}


def register_mutation(name: str) -> Callable[[MutationFn], MutationFn]:
    def deco(fn: MutationFn) -> MutationFn:
        _MUTATIONS[name] = fn
        return fn
    return deco


@register_mutation("set_byte")
def _set_byte(payload: bytes, *, offset: int, value: int) -> bytes:
    b = bytearray(payload)
    b[offset] = value & 0xFF
    return bytes(b)


@register_mutation("xor_byte")
def _xor_byte(payload: bytes, *, offset: int, mask: int) -> bytes:
    b = bytearray(payload)
    b[offset] ^= mask & 0xFF
    return bytes(b)


@register_mutation("increment_byte")
def _inc_byte(payload: bytes, *, offset: int, by: int = 1) -> bytes:
    b = bytearray(payload)
    b[offset] = (b[offset] + by) & 0xFF
    return bytes(b)


@register_mutation("replace")
def _replace(payload: bytes, *, hex: str) -> bytes:
    return bytes.fromhex(hex)


def apply_mutation(payload: bytes, mutation: dict[str, Any] | None) -> bytes:
    if not mutation:
        return payload
    name = mutation.get("strategy") or mutation.get("name")
    if not name:
        return payload
    fn = _MUTATIONS.get(name)
    if not fn:
        raise ValueError(f"Unknown mutation strategy '{name}' (registered: {list(_MUTATIONS)})")
    kwargs = {k: v for k, v in mutation.items() if k not in ("strategy", "name")}
    return fn(payload, **kwargs)


@dataclass
class ReplayStep:
    handle: int | None = None
    char_uuid: str | None = None
    payload_hex: str = ""
    delay_before_ms: int = 0
    write_with_response: bool = True
    mutation: dict[str, Any] | None = None  # passed through to apply_mutation


@dataclass
class ReplayObservation:
    ts: float
    kind: str  # 'write_ack' / 'notify' / 'indicate' / 'error'
    handle: int | None
    char_uuid: str | None
    payload_hex: str | None
    error: str | None = None


@dataclass
class ReplayResult:
    target_mac: str
    sent: list[dict] = field(default_factory=list)
    observations: list[ReplayObservation] = field(default_factory=list)
    status: str = "ok"
    error: str | None = None
    started_at: float = 0.0
    ended_at: float | None = None


async def run_replay(
    target_mac: str,
    steps: list[ReplayStep],
    *,
    session_id: int | None = None,
    listen_for_notifications_ms: int = 1000,
) -> ReplayResult:
    """Connect to a peripheral, run each step, gather notifications, record to DB.

    Works on macOS via CoreBluetooth (which means you address devices by UUID, not
    MAC, on macOS — bleak handles that translation if you scan first).
    """
    from bleak import BleakClient, BleakScanner  # lazy import: keeps `bt-spy --help` fast

    result = ReplayResult(target_mac=target_mac, started_at=time.time())

    # On macOS Core Bluetooth never exposes raw MACs; bleak gives us an
    # internal CBPeripheralIdentifier. If the user passes a CB UUID, use it
    # directly; otherwise scan briefly to find the device.
    address_to_use = target_mac
    try:
        # If the format isn't a UUID, do a quick scan to map name → identifier.
        if "-" not in target_mac and len(target_mac.replace(":", "")) != 12:
            log.info("Scanning for %s …", target_mac)
            dev = await BleakScanner.find_device_by_name(target_mac, timeout=10.0)
            if dev:
                address_to_use = dev.address
    except Exception:
        pass

    try:
        async with BleakClient(address_to_use, timeout=20.0) as client:
            # Subscribe to all notify-able characteristics so we capture device responses.
            notify_chars: list[str] = []
            try:
                for svc in client.services:
                    for ch in svc.characteristics:
                        if "notify" in ch.properties or "indicate" in ch.properties:
                            await client.start_notify(
                                ch.uuid,
                                _make_notify_callback(result, ch.uuid),
                            )
                            notify_chars.append(ch.uuid)
            except Exception as exc:
                log.warning("Could not subscribe to notifications: %s", exc)

            for step in steps:
                if step.delay_before_ms:
                    await asyncio.sleep(step.delay_before_ms / 1000.0)
                raw = bytes.fromhex(step.payload_hex)
                if step.mutation:
                    raw = apply_mutation(raw, step.mutation)
                target = step.char_uuid or _handle_to_char_uuid(client, step.handle)
                if target is None:
                    result.status = "error"
                    result.error = f"Could not resolve target (handle={step.handle}, uuid={step.char_uuid})"
                    break
                try:
                    await client.write_gatt_char(
                        target, raw, response=step.write_with_response
                    )
                    result.observations.append(ReplayObservation(
                        ts=time.time(),
                        kind="write_ack",
                        handle=step.handle,
                        char_uuid=target,
                        payload_hex=raw.hex(),
                    ))
                    result.sent.append({
                        "handle": step.handle,
                        "char_uuid": target,
                        "payload_hex": raw.hex(),
                        "with_response": step.write_with_response,
                    })
                except Exception as exc:
                    result.observations.append(ReplayObservation(
                        ts=time.time(),
                        kind="error",
                        handle=step.handle,
                        char_uuid=target,
                        payload_hex=raw.hex(),
                        error=str(exc),
                    ))
                    result.status = "error"
                    result.error = str(exc)
                    break

            # Linger to collect notifications triggered by the final write
            await asyncio.sleep(listen_for_notifications_ms / 1000.0)

            for uuid in notify_chars:
                try:
                    await client.stop_notify(uuid)
                except Exception:
                    pass
    except Exception as exc:
        result.status = "error"
        result.error = str(exc)

    result.ended_at = time.time()

    # Persist
    try:
        conn = db.init_db()
        db.record_replay(
            conn,
            session_id=session_id,
            target_mac=target_mac,
            sent=result.sent,
            response=[o.__dict__ for o in result.observations],
            status=result.status,
            error=result.error,
            started_at=result.started_at,
            ended_at=result.ended_at,
        )
    except Exception as exc:
        log.warning("Failed to persist replay: %s", exc)

    return result


def _make_notify_callback(result: ReplayResult, char_uuid: str):
    def cb(_sender, data: bytearray) -> None:
        result.observations.append(ReplayObservation(
            ts=time.time(),
            kind="notify",
            handle=None,
            char_uuid=char_uuid,
            payload_hex=bytes(data).hex(),
        ))
    return cb


def _handle_to_char_uuid(client, handle: int | None) -> str | None:
    if handle is None:
        return None
    try:
        for svc in client.services:
            for ch in svc.characteristics:
                if getattr(ch, "handle", None) == handle:
                    return ch.uuid
    except Exception:
        return None
    return None


def run_replay_sync(target_mac: str, steps: list[ReplayStep], **kw) -> ReplayResult:
    return asyncio.run(run_replay(target_mac, steps, **kw))


@dataclass
class SweepRequest:
    target: str                  # device name or CB UUID
    char_uuid: str
    base_payload_hex: str
    offset: int                  # which byte to sweep
    value_start: int = 0
    value_end: int = 255         # inclusive
    step: int = 1
    delay_ms: int = 200          # between writes
    listen_ms_per_step: int = 0  # collect notifications after each write
    write_with_response: bool = False


async def run_sweep(req: SweepRequest, *, session_id: int | None = None) -> ReplayResult:
    """Generate one ReplayStep per value in the sweep range and run them.

    Each step uses the `set_byte` mutation strategy to overwrite the byte at
    `req.offset` with the current value, leaving the rest of the base payload
    intact. The full run is recorded as a single Replay row in the DB.
    """
    base = bytes.fromhex(req.base_payload_hex)
    steps: list[ReplayStep] = []
    for v in range(req.value_start, req.value_end + 1, req.step):
        steps.append(ReplayStep(
            char_uuid=req.char_uuid,
            payload_hex=base.hex(),
            mutation={"strategy": "set_byte", "offset": req.offset, "value": v},
            delay_before_ms=req.delay_ms if steps else 0,
            write_with_response=req.write_with_response,
        ))
    return await run_replay(
        req.target, steps,
        session_id=session_id,
        listen_for_notifications_ms=req.listen_ms_per_step or 500,
    )
