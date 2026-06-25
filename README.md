# bt-spy — BLE protocol reverse-engineering workstation

Sniff Bluetooth Low Energy traffic with a $10 nRF52840 dongle, store every packet in
SQLite, diff sessions to find commands, replay them with mutations to confirm
their meaning, and let Claude drive the whole thing through an MCP server.

Built for **macOS** and for people who have never reverse-engineered a wireless
protocol before. There is a web UI with a "Flash dongle" button — that is the
hardest step.

```
                                ┌──────────────┐
   ┌─────────────┐    pcap-ng   │  bt-spy      │  WebSocket   ┌────────────┐
   │  nRF52840   ├──USB serial─►│   capture    ├─────────────►│  Web UI    │
   │  (sniffer)  │              │   daemon     │              │ (browser)  │
   └─────────────┘              └──────┬───────┘              └────────────┘
                                       │ SQLite                      ▲
                                       ▼                             │
                                ┌──────────────┐                     │
                                │   protocol   │  REST + WS          │
                                │   dictionary │◄────────────────────┘
                                │   sessions   │
                                │   packets    │  MCP stdio
                                └──────┬───────┘──────────────►  Claude
                                       │
                                       ▼
                                ┌──────────────┐    BLE (host)   ┌────────────┐
                                │   replay     ├────────────────►│  Real BLE  │
                                │   engine     │                 │   device   │
                                └──────────────┘                 └────────────┘
```

## Quick start

```bash
# 1. Install
pip install -e .

# 2. Check your environment
bt-spy doctor

# 3. Plug in the dongle. Press its small white RESET button (LED pulses red).
#    Then flash sniffer firmware:
bt-spy flash

# 4. Run the UI
bt-spy serve
# → open http://127.0.0.1:8765
```

For Claude to drive bt-spy, add this to your Claude Code config (`~/.claude.json`
or via `claude mcp add`):

```json
{
  "mcpServers": {
    "bt-spy": { "command": "bt-spy", "args": ["mcp"] }
  }
}
```

## What's in here

| Folder                   | Contents                                                          |
| ------------------------ | ----------------------------------------------------------------- |
| `src/bt_spy/capture/`    | nRF sniffer extcap wrapper + pcap-ng parser + capture daemon      |
| `src/bt_spy/firmware/`   | One-button DFU flashing (download → unpack → flash)               |
| `src/bt_spy/replay/`     | bleak-based GATT writes + pluggable mutation strategies           |
| `src/bt_spy/analysis/`   | Session diff, handle summary, naive field-structure inference     |
| `src/bt_spy/decoders/`   | Drop-in built-in decoders                                         |
| `src/bt_spy/api/`        | FastAPI REST + WebSocket + SSE-streamed flash progress            |
| `src/bt_spy/mcp/`        | MCP server exposing every capability to Claude                    |
| `src/bt_spy/web/`        | Single-page UI (no build step)                                    |
| `src/bt_spy/cli.py`      | Typer CLI: doctor, flash, capture, sessions, diff, replay, serve, mcp |
| `docs/`                  | Design, user guide, firmware, RE tutorial                         |

## Documentation

- [docs/design.md](docs/design.md) — Architecture, data model, extension points.
- [docs/user-guide.md](docs/user-guide.md) — Install, run, the UI, the CLI, the MCP.
- [docs/firmware-flashing.md](docs/firmware-flashing.md) — Dongle setup in detail.
- [docs/protocol-re-tutorial.md](docs/protocol-re-tutorial.md) — Walk through reverse-engineering a fictional smart bulb end-to-end.
- [docs/packetlogger.md](docs/packetlogger.md) — Sniff the Mac's own Bluetooth stack via PacketLogger (no dongle needed for Mac-side captures).
- [docs/home-assistant.md](docs/home-assistant.md) — Export Python drivers, scaffold custom_components, or run as an MQTT bridge.

## License

MIT.
