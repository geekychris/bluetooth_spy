"""Flash the nRF52840 USB Dongle with Nordic's BLE Sniffer firmware.

The nRF52840 USB Dongle (PCA10059) ships with a permanent open bootloader, so the
host-side flow is:

  1. Plug in the dongle. If the red LED isn't pulsing, press the small white reset
     button on the side — it'll enter DFU mode (LED pulses).
  2. We download the sniffer firmware zip from Nordic (cached on disk).
  3. We run `nrfutil dfu usb-serial -pkg <zip> -p <port>` to push it.

We expose a single `flash(progress_cb)` function so the CLI, web button, and MCP
tool can all call the same code path.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests

from ..capture.extcap import find_dongle_port
from ..config import settings

log = logging.getLogger(__name__)


# Nordic publishes the sniffer software (which contains the firmware zip + extcap)
# at a stable URL. We pin a version to keep behaviour reproducible; users can
# override with BTSPY_SNIFFER_URL.
DEFAULT_SNIFFER_URL = (
    "https://www.nordicsemi.com/-/media/Software-and-other-downloads/Desktop-software/"
    "nRF-Sniffer/sw/nrf_sniffer_for_bluetooth_le_4.1.1.zip"
)
SNIFFER_ZIP_NAME = "nrf_sniffer_for_bluetooth_le.zip"
# Inside the unpacked archive, this is the dongle firmware:
EXPECTED_FIRMWARE_GLOB = "**/sniffer_pca10059_*.zip"
# And this is the extcap script we want to copy out:
EXPECTED_EXTCAP_GLOB = "**/nrf_sniffer_ble.py"


@dataclass
class FlashResult:
    ok: bool
    message: str
    port: str | None = None
    firmware_path: Path | None = None
    extcap_path: Path | None = None


ProgressFn = Callable[[str, float | None], None]  # (message, percent 0..1 or None)


def _progress(cb: ProgressFn | None, msg: str, pct: float | None = None) -> None:
    if cb:
        try:
            cb(msg, pct)
        except Exception:
            pass
    log.info("[flash %s] %s", f"{pct*100:.0f}%" if pct is not None else "...", msg)


def have_nrfutil() -> bool:
    return shutil.which("nrfutil") is not None


NORDIC_DOWNLOAD_PAGE = "https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE/Download"


class SnifferDownloadForbidden(RuntimeError):
    """Nordic returned 403 — likely a URL change or anti-scraping. Caller should
    surface a helpful message asking the user to download manually."""


def download_sniffer_bundle(progress_cb: ProgressFn | None = None) -> Path:
    """Download Nordic's sniffer zip into the cache dir. Idempotent.

    Raises SnifferDownloadForbidden if Nordic returns 403 (their CDN URL changed
    or they're rejecting non-browser clients). The caller should then prompt
    the user to download manually and re-run with bundle_path=...
    """
    settings.ensure_dirs()
    url = os.environ.get("BTSPY_SNIFFER_URL", DEFAULT_SNIFFER_URL)
    dest = settings.firmware_cache_dir / SNIFFER_ZIP_NAME
    if dest.exists() and dest.stat().st_size > 0:
        _progress(progress_cb, f"Using cached sniffer bundle at {dest}", 1.0)
        return dest

    _progress(progress_cb, f"Downloading sniffer bundle from {url}", 0.0)
    # Send a browser-ish User-Agent — Nordic's CDN sometimes rejects requests
    # without one. Doesn't help if they've moved the URL entirely.
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh) bt-spy/0.1"}
    try:
        with requests.get(url, stream=True, timeout=60, headers=headers) as r:
            if r.status_code == 403:
                raise SnifferDownloadForbidden(
                    f"Nordic returned 403 Forbidden for {url}. They've either moved the file "
                    f"or added anti-scraping. Download manually from {NORDIC_DOWNLOAD_PAGE} "
                    f"in a browser, then re-run `bt-spy flash --bundle <path-to-zip>`."
                )
            r.raise_for_status()
            total = int(r.headers.get("content-length") or 0)
            written = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 15):
                    if not chunk:
                        continue
                    f.write(chunk)
                    written += len(chunk)
                    if total:
                        _progress(progress_cb, "downloading", written / total)
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 403:
            raise SnifferDownloadForbidden(str(exc)) from exc
        raise
    _progress(progress_cb, f"Saved bundle to {dest}", 1.0)
    return dest


def use_local_bundle(path: Path, progress_cb: ProgressFn | None = None) -> Path:
    """Copy a user-supplied sniffer zip into the cache and return the cached path."""
    settings.ensure_dirs()
    dest = settings.firmware_cache_dir / SNIFFER_ZIP_NAME
    if path.resolve() == dest.resolve():
        return dest
    shutil.copy2(path, dest)
    _progress(progress_cb, f"Using local bundle at {dest}", 1.0)
    return dest


def unpack_sniffer_bundle(bundle: Path, progress_cb: ProgressFn | None = None) -> Path:
    """Unpack bundle into firmware_cache_dir/extracted and return that path."""
    out_dir = settings.firmware_cache_dir / "extracted"
    if out_dir.exists() and any(out_dir.iterdir()):
        return out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    _progress(progress_cb, f"Extracting {bundle.name}", 0.0)
    with zipfile.ZipFile(bundle) as z:
        z.extractall(out_dir)
    _progress(progress_cb, "Extracted", 1.0)
    return out_dir


def locate_firmware(extracted_dir: Path) -> Path:
    matches = list(extracted_dir.rglob("sniffer_pca10059_*.zip"))
    if not matches:
        # Some bundles ship as .hex
        matches = list(extracted_dir.rglob("sniffer_pca10059_*.hex"))
    if not matches:
        raise FileNotFoundError(
            f"Could not find sniffer_pca10059_*.zip in {extracted_dir}. "
            "Did Nordic change their bundle layout?"
        )
    matches.sort()
    return matches[-1]


def locate_extcap(extracted_dir: Path) -> Path | None:
    matches = list(extracted_dir.rglob("nrf_sniffer_ble.py"))
    return matches[0] if matches else None


def flash(
    progress_cb: ProgressFn | None = None,
    *,
    port: str | None = None,
    wait_for_dongle_secs: float = 30.0,
    bundle_path: Path | None = None,
) -> FlashResult:
    """End-to-end flash. Returns a FlashResult; never raises for the happy path."""
    if not have_nrfutil():
        return FlashResult(
            ok=False,
            message=(
                "nrfutil not found on PATH. Install with `pip install nrfutil` or "
                "download from https://github.com/NordicSemiconductor/pc-nrfutil/releases"
            ),
        )

    _progress(progress_cb, "Locating dongle…", None)
    p = port or find_dongle_port()
    deadline = time.time() + wait_for_dongle_secs
    while p is None and time.time() < deadline:
        time.sleep(1)
        p = find_dongle_port()
    if p is None:
        return FlashResult(
            ok=False,
            message=(
                "No nRF52840 dongle detected. Plug it in, then press the small white "
                "RESET button on the side (red LED should pulse). Then try again."
            ),
        )
    _progress(progress_cb, f"Found dongle at {p}", None)

    try:
        if bundle_path is not None:
            bundle = use_local_bundle(Path(bundle_path), progress_cb)
        else:
            try:
                bundle = download_sniffer_bundle(progress_cb)
            except SnifferDownloadForbidden as exc:
                return FlashResult(
                    ok=False,
                    message=(
                        str(exc) + "\n\nQuick fix: download the zip from a browser, "
                        f"then `bt-spy flash --bundle <path>` (or use the UI's bundle picker)."
                    ),
                    port=p,
                )
        extracted = unpack_sniffer_bundle(bundle, progress_cb)
        fw = locate_firmware(extracted)
        extcap_path = locate_extcap(extracted)
    except Exception as exc:
        return FlashResult(ok=False, message=f"Firmware preparation failed: {exc}")

    _progress(progress_cb, f"Flashing {fw.name} via DFU on {p}", None)
    cmd = ["nrfutil", "dfu", "usb-serial", "-pkg", str(fw), "-p", p]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return FlashResult(ok=False, message="DFU timed out after 120s", port=p)
    if proc.returncode != 0:
        return FlashResult(
            ok=False,
            message=f"nrfutil exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}",
            port=p,
        )

    _progress(progress_cb, "Flash complete", 1.0)
    # Stash the extcap path in settings for future capture sessions
    if extcap_path:
        _maybe_install_extcap(extcap_path, progress_cb)

    return FlashResult(
        ok=True,
        message="Sniffer firmware flashed; extcap script ready.",
        port=p,
        firmware_path=fw,
        extcap_path=extcap_path,
    )


def _maybe_install_extcap(src: Path, progress_cb: ProgressFn | None = None) -> None:
    """Copy the extcap script into the standard Wireshark extcap dir on macOS
    if Wireshark is installed (best-effort)."""
    candidates = [
        Path("/Applications/Wireshark.app/Contents/MacOS/extcap"),
        Path.home() / ".config" / "wireshark" / "extcap",
    ]
    for d in candidates:
        if d.exists():
            dest = d / src.name
            try:
                shutil.copy2(src, dest)
                os.chmod(dest, 0o755)
                _progress(progress_cb, f"Installed extcap → {dest}", None)
            except Exception as exc:
                _progress(progress_cb, f"Could not install extcap to {d}: {exc}", None)
