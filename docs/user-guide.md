# bt-spy — User guide

If you've never reverse-engineered a Bluetooth protocol, start here. We'll get
you to *capturing actual traffic* before we get into theory.

## What you need

- macOS (tested on 14+). Linux will likely work; Windows is untested.
- Python 3.11 or newer.
- **An nRF52840 USB Dongle** (Nordic Semiconductor PCA10059). ~$10–15 on Mouser,
  DigiKey, or Adafruit. Looks like a small USB stick.
- (Optional) Wireshark, if you want to also open the raw pcap files in their UI.

You do *not* need a JTAG programmer. The dongle's bootloader handles flashing
over USB.

## Install

```bash
git clone <this repo> bt-spy
cd bt-spy
pip install -e .
```

Then verify:

```bash
bt-spy doctor
```

You'll see something like:

```
┌──────────────────┬────────┬──────────────────────────────────────┐
│ check            │ status │ detail                               │
├──────────────────┼────────┼──────────────────────────────────────┤
│ data dir         │ ✓      │ /Users/you/.bt-spy                   │
│ db               │ ✓      │ /Users/you/.bt-spy/bt-spy.db         │
│ dongle           │ ✗      │ not detected — plug in + reset       │
│ sniffer extcap   │ ✗      │ not found — run `bt-spy flash`       │
│ nrfutil          │ ✓      │ found                                │
└──────────────────┴────────┴──────────────────────────────────────┘
```

If `nrfutil` is missing: `pip install nrfutil`.

## Flash the dongle

1. Plug the dongle into a USB-A port (use a USB-A → USB-C adapter on newer Macs).
2. Press the **small white button** on the side of the dongle. The red LED
   should start pulsing — that's DFU mode.
3. Run:

   ```bash
   bt-spy flash
   ```

   Or click **Flash sniffer firmware** in the web UI (`bt-spy serve` → Dongle tab).

The first run downloads Nordic's sniffer bundle (~5 MB) into `~/.bt-spy/firmware-cache/`.
Subsequent runs use the cache. The actual DFU takes ~15 seconds.

After flashing, the dongle re-enumerates as a *Nordic Sniffer* serial port.
`bt-spy doctor` should now show ✓ for both *dongle* and *sniffer extcap*.

Detailed troubleshooting: [firmware-flashing.md](firmware-flashing.md).

## Capture your first traffic

Quickest path with the CLI:

```bash
bt-spy capture baseline --notes "device idle, no app open"
# … wait ~30s, then Ctrl-C …

bt-spy capture tap_on --notes "tapped Power On in vendor app"
# … perform the action you want to understand, then Ctrl-C …

bt-spy sessions
bt-spy diff 1 2     # baseline=1, candidate=2
```

The `diff` output shows new (handle, payload) pairs — these are the packets the
vendor app sent to make the device do the thing.

Same thing in the web UI: Capture tab → enter label → Start. Repeat with a
different label for the action you're investigating. Then Diff tab.

## Replay a packet to confirm

```bash
bt-spy replay "MiSmartLight" \
  '[{"char_uuid":"0000fff1-0000-1000-8000-00805f9b34fb","payload_hex":"01ff","write_with_response":false}]'
```

The target can be either:
- a name (we'll BLE-scan briefly to resolve)
- a CoreBluetooth peripheral UUID (`5A7F1234-...`) — what bleak hands back from
  a scan on macOS, since Apple hides MAC addresses

Step fields:

| field                  | type | meaning                                                  |
| ---------------------- | ---- | -------------------------------------------------------- |
| `handle`               | int  | ATT handle. Optional if you give a UUID.                 |
| `char_uuid`            | str  | Characteristic UUID. Either this or `handle`.            |
| `payload_hex`          | str  | Bytes to write, hex-encoded (`01ff` = 0x01, 0xFF).       |
| `delay_before_ms`      | int  | Wait before sending this step.                           |
| `write_with_response`  | bool | True → write-request (ack expected). False → write-cmd.  |
| `mutation`             | obj  | Optional. See below.                                     |

### Mutations

Replay the same byte string with a single byte mutated, and see what the device
does. Built-in strategies:

| strategy            | args                                          |
| ------------------- | --------------------------------------------- |
| `set_byte`          | `{offset, value}` — overwrite one byte         |
| `xor_byte`          | `{offset, mask}` — XOR one byte               |
| `increment_byte`    | `{offset, by?}` — add to one byte             |
| `replace`           | `{hex}` — replace the whole payload           |

Example: try every brightness from 0..255 against handle 0x24:

```bash
for i in $(seq 0 16 255); do
  hex=$(printf "%02x" "$i")
  bt-spy replay MiSmartLight \
    "[{\"handle\":36,\"payload_hex\":\"01$hex\",\"write_with_response\":false}]"
  sleep 0.2
done
```

(`36 = 0x24`. Use the diff results to find the right handle.)

## Run the web UI

```bash
bt-spy serve
```

Open http://127.0.0.1:8765. Tabs:

- **Dashboard** — getting-started checklist.
- **Capture** — start/stop sessions, live packet feed via WebSocket.
- **Sessions** — list, drill in, run handle summary.
- **Diff** — pick baseline + candidate, see new packets.
- **Replay** — same as the CLI command, in a form.
- **Protocol Dict** — the knowledge accumulator. Once you've confirmed
  "handle 36 + payload `[01, brightness]` = set brightness", save it here.
- **Dongle** — health + the big flash button.

## Let Claude drive it

The MCP server exposes every capability listed above (plus `infer_structure`,
which gives Claude a starting hypothesis for what fields a payload encodes).

Add to your Claude Code config (`~/.claude.json` or via `claude mcp add`):

```json
{
  "mcpServers": {
    "bt-spy": {
      "command": "bt-spy",
      "args": ["mcp"]
    }
  }
}
```

Then in a Claude conversation:

> Look at session 5. It's me tapping the brightness slider in the vendor app
> from min to max. What handle is the command going to and what's the encoding?

Claude will call `get_packets(session_id=5)` and `handle_summary(session_id=5)`,
notice that handle 36 takes 5 different payloads with the same prefix `01` and
varying second byte, propose a decoder, and ask the `replay` tool to send
`01 80` to confirm it sets brightness to ~50%. Then `upsert_protocol_entry` to
persist the finding.

## What gets stored where

```
~/.bt-spy/
├── bt-spy.db                # the only durable state
└── firmware-cache/
    ├── nrf_sniffer_for_bluetooth_le.zip
    └── extracted/...
```

Back up `bt-spy.db` and you've got everything: sessions, packets, annotations,
protocol entries, replays. Move it to a new machine and everything Just Works.

## Useful environment variables

| var                          | what                                          | default                        |
| ---------------------------- | --------------------------------------------- | ------------------------------ |
| `BTSPY_DATA_DIR`             | where data + cache live                       | `~/.bt-spy`                    |
| `BTSPY_REST_HOST`            | UI server bind host                           | `127.0.0.1`                    |
| `BTSPY_REST_PORT`            | UI server bind port                           | `8765`                         |
| `BTSPY_SNIFFER_EXTCAP_PATH`  | override extcap script location               | auto-detected                  |
| `BTSPY_SNIFFER_URL`          | override sniffer firmware download URL        | Nordic's stable release        |
| `BTSPY_LOG_LEVEL`            | DEBUG / INFO / WARNING                        | INFO                           |

## Cheat sheet

```bash
bt-spy doctor                          # environment check
bt-spy flash                           # flash dongle with sniffer firmware
bt-spy capture LABEL                   # start capture (Ctrl-C to stop)
bt-spy sessions                        # list captures
bt-spy diff BASE CAND                  # diff two sessions
bt-spy replay TARGET 'JSON'            # replay GATT writes
bt-spy export SID -o session.jsonl     # JSONL dump for Claude
bt-spy serve                           # web UI
bt-spy mcp                             # MCP server (for Claude config)
```

## Next: see [protocol-re-tutorial.md](protocol-re-tutorial.md) for a worked example.
