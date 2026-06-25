"""Drive the nRF52840 sniffer via Nordic's `nrfutil ble-sniffer` subcommand.

Nordic deprecated the old `nrf_sniffer_ble.py` Python wrapper in nrfutil 8.x —
the sniffer subcommand is now a first-class part of the nrfutil binary. We
spawn `nrfutil ble-sniffer sniff` with `--output-pcap-file <tempfile>` and
tail that file the same way we tail PL.app's pklg in `iter_pklg_tail`.

Two paths supported:
  - **New path (nrfutil 8.x)**: spawn the binary directly. Output: classic pcap.
  - **Legacy path (nrf_sniffer_ble.py)**: kept around for users who haven't
    upgraded — searches the standard Wireshark extcap directories.

`find_extcap_script` falls back to legacy if nrfutil's ble-sniffer isn't present.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..config import settings

# Legacy: Wireshark extcap dirs where Nordic used to drop nrf_sniffer_ble.py.
DEFAULT_EXTCAP_SEARCH_PATHS = [
    Path("/Applications/Wireshark.app/Contents/MacOS/extcap"),
    Path.home() / ".config" / "wireshark" / "extcap",
    Path.home() / ".local" / "lib" / "wireshark" / "extcap",
    Path("/usr/local/lib/wireshark/extcap"),
    Path("/opt/homebrew/lib/wireshark/extcap"),
]

EXTCAP_SCRIPT_NAMES = ("nrf_sniffer_ble.py", "nrf_sniffer_ble.sh", "nrf_sniffer_ble.bat")


def find_nrfutil_binary() -> Path | None:
    """Locate the modern Nordic nrfutil binary (8.x) with the ble-sniffer subcommand
    installed. Returns None if missing or if only the old Python 6.x is on PATH.

    Detection: try `nrfutil ble-sniffer --help`. Exit code 0 means the subcommand
    is installed; non-zero means either the wrong nrfutil OR the subcommand wasn't
    installed via `nrfutil install ble-sniffer`.
    """
    p = shutil.which("nrfutil")
    if not p:
        return None
    binary = Path(p)
    try:
        out = subprocess.run(
            [str(binary), "ble-sniffer", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        return binary if out.returncode == 0 else None
    except Exception:
        return None


def find_extcap_script() -> Path | None:
    """Find the legacy Python wrapper. Honors BTSPY_SNIFFER_EXTCAP_PATH override.

    Returns None on nrfutil 8.x installs — those don't ship the Python script and
    use the binary path via `find_nrfutil_binary` instead.
    """
    if settings.sniffer_extcap_path:
        p = Path(settings.sniffer_extcap_path)
        return p if p.exists() else None
    for d in DEFAULT_EXTCAP_SEARCH_PATHS:
        if not d.exists():
            continue
        for name in EXTCAP_SCRIPT_NAMES:
            p = d / name
            if p.exists():
                return p
    return None


def find_dongle_port() -> str | None:
    """Return the /dev/cu.usbmodem* path for the connected dongle, if any.

    nRF52840 USB Dongles enumerate as Nordic Semiconductor (VID 0x1915). We use
    `pyserial`'s comports() to filter rather than globbing /dev — works on any OS.
    """
    try:
        from serial.tools import list_ports
    except ImportError:
        return None
    for p in list_ports.comports():
        vid = (p.vid or 0)
        if vid == 0x1915:
            return p.device
        # Fallback: device path heuristic on macOS
        if "usbmodem" in (p.device or "") and "Nordic" in (p.description or ""):
            return p.device
    # Last-resort: scan /dev for usbmodem entries (works if pyserial USB info missing)
    for name in os.listdir("/dev"):
        if name.startswith("cu.usbmodem"):
            return f"/dev/{name}"
    return None


@dataclass
class ExtcapSession:
    script: Path
    port: str
    process: subprocess.Popen


def start_extcap(
    script: Path | None = None,
    port: str | None = None,
    *,
    fifo: str = "/dev/stdout",
) -> ExtcapSession:
    """Launch the extcap script and return the running subprocess.

    Output (pcap-ng frames) flows to `process.stdout`. Caller is responsible for
    reading and parsing it, and for calling `.terminate()` when done.
    """
    s = script or find_extcap_script()
    if s is None:
        raise FileNotFoundError(
            "nRF Sniffer extcap script not found. Install Nordic's nRF Sniffer for "
            "Bluetooth LE (see docs/firmware-flashing.md) or set BTSPY_SNIFFER_EXTCAP_PATH."
        )
    p = port or find_dongle_port()
    if p is None:
        raise RuntimeError(
            "No nRF52840 dongle detected on any serial port. Plug it in, flash the "
            "sniffer firmware, and try again."
        )
    # The Nordic extcap script is a Python script invoked with a /usr/bin/env shebang.
    # We pass `--capture` plus the chosen interface and a fifo path; with /dev/stdout
    # the pcap stream comes back to us on the subprocess's stdout pipe.
    cmd = [
        str(s),
        "--capture",
        "--extcap-interface",
        f"COM-{p}",  # script accepts the port; quoting style varies by version.
        "--fifo",
        fifo,
    ]
    # Some Nordic releases prefer python invocation; respect shebang if it's a .py.
    if s.suffix == ".py" and not os.access(s, os.X_OK):
        cmd = ["python3", *cmd]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    return ExtcapSession(script=s, port=p, process=proc)


def have_wireshark() -> bool:
    return shutil.which("tshark") is not None or Path("/Applications/Wireshark.app").exists()


@dataclass
class NrfutilSniffSession:
    binary: Path
    port: str
    pcap_path: Path
    process: subprocess.Popen


def start_nrfutil_sniff(
    binary: Path | None = None,
    port: str | None = None,
    *,
    follow_address: str | None = None,
    follow_name: str | None = None,
    legacy_ltk_hex: str | None = None,
    sc_ltk_hex: str | None = None,
    irk_hex: str | None = None,
    only_advertising: bool = False,
) -> NrfutilSniffSession:
    """Spawn `nrfutil ble-sniffer sniff` writing classic pcap to a tempfile.

    Caller is responsible for tailing the pcap file (the daemon does that via
    `parser.iter_pcap_classic_tail`), and for `.terminate()`-ing the process
    on stop.
    """
    b = binary or find_nrfutil_binary()
    if b is None:
        raise FileNotFoundError(
            "Nordic nrfutil binary not found (or it's the old Python 6.x version). "
            "Install from https://www.nordicsemi.com/Products/Development-tools/nRF-Util/Download "
            "and run `nrfutil install ble-sniffer`."
        )
    p = port or find_dongle_port()
    if p is None:
        raise RuntimeError(
            "No nRF52840 dongle detected on any serial port. Plug it in, flash the "
            "sniffer firmware, and try again."
        )

    settings.ensure_dirs()
    tmp = settings.data_dir / "nrf-sniffer-tail"
    tmp.mkdir(parents=True, exist_ok=True)
    pcap_path = Path(tempfile.mkstemp(dir=tmp, suffix=".pcap", prefix="capture_")[1])

    cmd: list[str] = [
        str(b), "ble-sniffer", "sniff",
        "--port", p,
        "--output-pcap-file", str(pcap_path),
    ]
    if follow_address:
        cmd += ["--follow", follow_address]
    elif follow_name:
        cmd += ["--follow-by-name", follow_name]
    if legacy_ltk_hex:
        cmd += ["--legacy-ltk-key", legacy_ltk_hex]
    if sc_ltk_hex:
        cmd += ["--sc-ltk-key", sc_ltk_hex]
    if irk_hex:
        cmd += ["--irk-key", irk_hex]
    if only_advertising:
        cmd += ["--only-advertising"]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    return NrfutilSniffSession(binary=b, port=p, pcap_path=pcap_path, process=proc)
