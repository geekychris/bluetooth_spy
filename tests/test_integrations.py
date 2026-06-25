"""Test code generation: driver export + HA scaffold.

Strategy:
  - Plant a few protocol_entries representative of a light + sensor.
  - Generate the driver / scaffold.
  - Assert: outputs parse as valid Python, key class/function names appear.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from bt_spy import db
from bt_spy.integrations import driver, homeassistant, vocabulary


@pytest.fixture
def populated_conn(tmp_path: Path, monkeypatch):
    """Point bt_spy.db at a temp DB and populate with a representative device."""
    from bt_spy import config
    monkeypatch.setattr(config.settings, "data_dir", tmp_path)
    monkeypatch.setattr(config.settings, "db_filename", "t.db")
    conn = db.init_db()

    # A light: power + brightness, and a battery_level read
    db.upsert_protocol_entry(
        conn, device_name="MiSmartLight", handle=36,
        char_uuid="0000fff1-0000-1000-8000-00805f9b34fb",
        direction="central->peripheral", name="power",
        structure=[{"offset": 0, "length": 1, "name": "cmd"}],
        encoder_py="def encode(on): return bytes([0x01, int(bool(on)), 0xff, 0x7e])",
        confidence=0.95,
    )
    db.upsert_protocol_entry(
        conn, device_name="MiSmartLight", handle=36,
        char_uuid="0000fff1-0000-1000-8000-00805f9b34fb",
        direction="central->peripheral", name="set_brightness",
        structure=[{"offset": 0, "length": 1, "name": "cmd"},
                   {"offset": 1, "length": 1, "name": "level"}],
        encoder_py="def encode(level): return bytes([0x02, level & 0xff, 0xff, 0x7e])",
        confidence=0.9,
    )
    db.upsert_protocol_entry(
        conn, device_name="MiSmartLight", handle=40,
        char_uuid="00002a19-0000-1000-8000-00805f9b34fb",
        direction="peripheral->central", name="battery_level",
        structure=[{"offset": 0, "length": 1, "name": "percent"}],
        decoder_py="def decode(payload): return payload[0]",
        confidence=1.0,
    )
    return conn


def test_vocabulary_classification():
    assert vocabulary.WRITES_TO_PLATFORM["set_brightness"] == ("light", "brightness")
    assert vocabulary.READS_TO_PLATFORM["battery_level"][0] == "sensor"
    # Power + brightness should collapse onto a light, not switch + light.
    out = vocabulary.classify_writes(["power", "set_brightness"])
    assert "light" in out and "switch" not in out
    assert set(out["light"]) >= {"power", "set_brightness"}


def test_driver_codegen_parses_and_has_methods(populated_conn):
    code = driver.generate_driver_code("MiSmartLight")
    # Parses as Python
    tree = ast.parse(code)
    # Has a top-level class with the camel name
    classes = [n.name for n in tree.body if isinstance(n, ast.ClassDef)]
    assert "MiSmartLight" in classes
    # Has methods for both writes and the read
    method_names = {
        n.name for c in tree.body if isinstance(c, ast.ClassDef)
        for n in c.body if isinstance(n, ast.AsyncFunctionDef)
    }
    assert "power" in method_names
    assert "set_brightness" in method_names
    assert "battery_level" in method_names
    # The encoder snippet was renamed to _encode_<method>
    assert "_encode_power" in code
    assert "_encode_set_brightness" in code
    assert "_decode_battery_level" in code
    # The notify uuid registry includes the battery characteristic
    assert "00002a19-0000-1000-8000-00805f9b34fb" in code


def test_ha_scaffold_writes_expected_files(populated_conn, tmp_path):
    out = tmp_path / "cc"
    paths = homeassistant.scaffold("MiSmartLight", out)
    names = {p.name for p in paths}
    assert {"manifest.json", "__init__.py", "const.py", "config_flow.py",
            "coordinator.py", "driver.py", "light.py", "sensor.py", "README.md"} <= names

    # manifest is valid JSON with the right domain
    manifest = json.loads((out / "mismartlight" / "manifest.json").read_text())
    assert manifest["domain"] == "mismartlight"
    assert manifest["config_flow"] is True
    assert manifest["dependencies"] == ["bluetooth"]
    assert manifest["bluetooth"], "must declare at least one bluetooth matcher"

    # Every generated .py parses as Python (would fail HA's import otherwise)
    for p in paths:
        if p.suffix == ".py":
            ast.parse(p.read_text(), filename=str(p))


def test_ha_scaffold_with_hints(populated_conn, tmp_path):
    out = tmp_path / "cc2"
    hints = homeassistant.ScaffoldHints(
        local_name="MiLight*", service_uuid="0000fff0-0000-1000-8000-00805f9b34fb",
        manufacturer_id=0x038F,
    )
    homeassistant.scaffold("MiSmartLight", out, hints)
    manifest = json.loads((out / "mismartlight" / "manifest.json").read_text())
    matcher = manifest["bluetooth"][0]
    assert matcher["local_name"] == "MiLight*"
    assert matcher["service_uuid"] == "0000fff0-0000-1000-8000-00805f9b34fb"
    assert matcher["manufacturer_id"] == 0x038F


def test_ha_scaffold_unknown_entry_yields_todo(populated_conn, tmp_path):
    conn = populated_conn
    db.upsert_protocol_entry(
        conn, device_name="MiSmartLight", handle=99,
        char_uuid="0000ffff-0000-1000-8000-00805f9b34fb",
        direction="central->peripheral", name="some_proprietary_thing",
        structure=[],
    )
    out = tmp_path / "cc3"
    homeassistant.scaffold("MiSmartLight", out, homeassistant.ScaffoldHints())
    todo = (out / "mismartlight" / "TODO.md")
    assert todo.exists()
    assert "some_proprietary_thing" in todo.read_text()
