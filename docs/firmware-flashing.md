# Firmware flashing — the nRF52840 USB Dongle

bt-spy turns a stock $10 dongle into a BLE sniffer. This page is the deep-dive
in case the one-liner (`bt-spy flash`) doesn't work the first time.

## What you have

The **nRF52840 USB Dongle** (Nordic part number PCA10059) is a stick-shaped
USB-A device with:

- One small **white reset button** on the side
- One **red LED** (status)
- One **multicolor LED** (RGB, used by firmware)
- A castellated edge with GPIOs (irrelevant for sniffing)

It ships with Nordic's **open bootloader** in unprotected flash. That means:

- You can DFU-update it over USB indefinitely.
- You don't need a JTAG/SWD programmer.
- You also don't need to be a registered Nordic developer.

## The flow

```
   ┌─────────────┐                ┌──────────────┐                ┌──────────────┐
   │  cold plug  │  press RESET   │   bootloader │   nrfutil      │   sniffer    │
   │  (running   ├───────────────►│   (LED       ├───────────────►│   firmware   │
   │   whatever) │                │   pulsing)   │   DFU push     │   (running)  │
   └─────────────┘                └──────────────┘                └──────────────┘
```

Two USB enumerations happen here, with different VID/PIDs:
- **Bootloader**: `1915:521f` — accepts DFU commands
- **Sniffer**: `1915:c00a` — exposes a CDC serial port over which the host
  sends sniffer-protocol requests

`bt-spy` doesn't care about VID/PIDs directly; we just find any
`/dev/cu.usbmodem*` from Nordic.

## The one-button flow

```bash
bt-spy flash
```

What it does:

1. **Find the dongle.** Looks for a Nordic VID on any USB serial port.
   Will wait up to 30 s for one to appear so you can plug it in after starting.
2. **Download the sniffer bundle** from Nordic (only first time, ~5 MB).
   Cached at `~/.bt-spy/firmware-cache/nrf_sniffer_for_bluetooth_le.zip`.
3. **Unpack** it. The bundle contains:
   - `sniffer_pca10059_*.zip` — the actual firmware DFU package
   - `extcap/nrf_sniffer_ble.py` — Nordic's host-side capture script
   - PDFs and other resources we don't need
4. **Run nrfutil DFU** against the dongle:
   `nrfutil dfu usb-serial -pkg <fw>.zip -p /dev/cu.usbmodemXXXX`.
5. **Install the extcap script** into `/Applications/Wireshark.app/Contents/MacOS/extcap/`
   if Wireshark is present, so you can also use Wireshark on the same dongle.

## Pressing the reset button

This is the one manual step. The bootloader only listens for DFU traffic when
the dongle is in DFU mode. To enter DFU mode:

- **First time:** sometimes the dongle is already in DFU mode after a cold plug
  (red LED slowly pulsing). If so, skip the button press.
- **Otherwise:** with the dongle plugged in, press the small white button
  exactly once. The red LED should start pulsing within ~500 ms.
- **Re-flashing later:** once you've already flashed sniffer firmware, the
  dongle boots into the sniffer (no LED pulse). You must press the white
  button to get back into the bootloader before flashing again.

If the LED doesn't pulse:
- Try a different USB port. Bootloader DFU is reliable but the dongle's USB
  data lines are tight against the casing; a hub or extension cable helps.
- Confirm the dongle is the PCA10059 variant. Older Nordic dongles (PCA10056,
  Decawave PCA10006) have different bootloaders.

## When `bt-spy flash` fails

### "No nRF52840 dongle detected"

The dongle isn't enumerating. Check:

```bash
ls /dev/cu.usbmodem*
ioreg -p IOUSB -l -w 0 | grep -i nordic
```

If nothing — the dongle isn't presenting itself. Re-seat it, press the reset
button, and try again.

### "nrfutil not found on PATH"

```bash
pip install nrfutil
which nrfutil   # should resolve
```

Some Pythons install scripts to `~/.local/bin` or your venv's `bin/`. Either
add to PATH or invoke `bt-spy` from inside the venv.

### "DFU timed out after 120s"

Most common cause: the dongle is in sniffer-firmware mode, not bootloader.
Press the white reset button to enter bootloader, then re-run.

Second cause: the version of `nrfutil` you have doesn't speak the dongle's DFU
protocol. The dongle's bootloader uses the "secure DFU" transport over USB
serial. `nrfutil` v6.x supports it; v3.x doesn't.

```bash
nrfutil version
# nrfutil version 6.1.7   ← good
```

### "Firmware preparation failed"

Either the download from Nordic failed (transient — try again) or the zip
layout changed (Nordic occasionally restructures their bundle). To force a
re-download:

```bash
rm -rf ~/.bt-spy/firmware-cache
bt-spy flash
```

If they really did restructure, override the URL:

```bash
BTSPY_SNIFFER_URL=https://example.com/your/mirror.zip bt-spy flash
```

## Manual flashing (without bt-spy)

You shouldn't need this, but for completeness:

```bash
# 1. Download Nordic's bundle from
#    https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-bluetooth-le
# 2. Unzip. Locate sniffer_pca10059_*.zip inside.
# 3. Put dongle in DFU mode (press white button).
# 4. ls /dev/cu.usbmodem*    # find the port
# 5. nrfutil dfu usb-serial -pkg sniffer_pca10059_*.zip -p /dev/cu.usbmodemXXXX
```

## Verifying the flash worked

```bash
bt-spy doctor
```

Both `dongle` and `sniffer extcap` should show ✓. If `sniffer extcap` is ✗,
the firmware is flashed but the host-side extcap script isn't in a standard
location. You can either:

- Point `BTSPY_SNIFFER_EXTCAP_PATH` at the extracted location:
  `~/.bt-spy/firmware-cache/extracted/.../nrf_sniffer_ble.py`
- Or symlink it into `~/.config/wireshark/extcap/`.

Once both are green, you're ready to capture.
