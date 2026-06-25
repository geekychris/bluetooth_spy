"""Decoder framework — pluggable Python snippets that turn raw payloads into dicts.

Two kinds:
  - Built-in decoders (registered via @register_decoder("device:handle:dir")) live
    in src/bt_spy/decoders/ as small Python modules.
  - User/Claude-authored decoders live in the DB (protocol_entries.decoder_py)
    as snippet bodies. They run in a restricted exec environment so a typo can't
    nuke your DB. This is RE tooling — not a sandbox — but we at least avoid
    obvious footguns.

A decoder snippet body should define `decode(payload: bytes) -> dict`. Example:

    def decode(payload):
        return {"cmd": payload[0], "value": int.from_bytes(payload[1:3], "big")}
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any, Callable

log = logging.getLogger(__name__)

DecoderFn = Callable[[bytes], dict[str, Any]]
_REGISTRY: dict[str, DecoderFn] = {}


def register_decoder(key: str) -> Callable[[DecoderFn], DecoderFn]:
    """Decorator: register a built-in decoder under key 'device:handle:direction'."""
    def deco(fn: DecoderFn) -> DecoderFn:
        _REGISTRY[key] = fn
        return fn
    return deco


def lookup_builtin(device_name: str | None, handle: int, direction: str) -> DecoderFn | None:
    if device_name:
        key = f"{device_name}:{handle}:{direction}"
        if key in _REGISTRY:
            return _REGISTRY[key]
    return _REGISTRY.get(f"*:{handle}:{direction}")


def compile_snippet(body: str) -> DecoderFn:
    """Compile a `def decode(...)` snippet into a callable."""
    namespace: dict[str, Any] = {}
    code = compile(body, "<protocol_entry_decoder>", "exec")
    exec(code, {"__builtins__": _safe_builtins()}, namespace)
    fn = namespace.get("decode")
    if not callable(fn):
        raise ValueError("Snippet must define `def decode(payload): ...`")
    return fn


def _safe_builtins() -> dict[str, Any]:
    safe = ["len", "int", "float", "str", "bytes", "bytearray", "list", "dict", "tuple",
            "range", "enumerate", "zip", "map", "filter", "sum", "min", "max", "abs",
            "round", "any", "all", "sorted", "reversed", "bool", "hex", "bin", "oct",
            "ord", "chr", "isinstance", "True", "False", "None"]
    return {k: __builtins__[k] if isinstance(__builtins__, dict) else getattr(__builtins__, k)
            for k in safe}


def decode_with_entry(conn: sqlite3.Connection, entry_id: int, payload: bytes) -> dict:
    row = conn.execute(
        "SELECT decoder_py FROM protocol_entries WHERE id=?", (entry_id,)
    ).fetchone()
    if not row or not row["decoder_py"]:
        raise ValueError(f"Protocol entry {entry_id} has no decoder")
    return compile_snippet(row["decoder_py"])(payload)


def autoload_builtin_decoders() -> None:
    """Import all modules under bt_spy.decoders so their @register_decoder calls run."""
    import importlib
    import pkgutil
    from .. import decoders
    for mod in pkgutil.iter_modules(decoders.__path__):
        try:
            importlib.import_module(f"bt_spy.decoders.{mod.name}")
        except Exception as exc:
            log.warning("Failed to import decoder module %s: %s", mod.name, exc)
