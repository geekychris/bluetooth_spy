# Architecture

This is the deep dive into how bt-spy fits together. For *why* the architecture is
shaped this way, see [design.md](design.md). For *what the schema looks like*, see
[data-model.md](data-model.md).

## Top-level layers

```mermaid
flowchart TB
    subgraph capture["Capture layer"]
        direction LR
        nrf[capture/extcap.py<br/>nrfutil ble-sniffer wrapper]
        pl[capture/packetlogger.py<br/>.pklg parser + tail]
        probe[ble_host.py<br/>bleak scan/probe]
        parser[capture/parser.py<br/>BTLE / HCI / Nordic decoders]
        daemon[capture/daemon.py<br/>CaptureDaemon - source-agnostic loop]
    end

    subgraph storage["Storage layer"]
        direction LR
        db[db.py<br/>schema, migrations, queries]
        sqlite[(SQLite WAL<br/>~/.bt-spy/bt-spy.db)]
    end

    subgraph analysis["Analysis layer"]
        direction LR
        diff[analysis/diff.py<br/>session + handle stats]
        checksum[analysis/checksum.py<br/>CRC/sum brute-force]
        decoder[analysis/decoder.py<br/>built-in + user snippets]
    end

    subgraph io["Interface layer"]
        direction LR
        rest[api/server.py<br/>FastAPI REST + WS + SSE]
        cli[cli.py<br/>Typer CLI]
        mcp[mcp/server.py<br/>MCP stdio for Claude]
    end

    subgraph ui["UI layer"]
        web[web/templates + static<br/>vanilla JS, no build step]
    end

    subgraph outputs["Output generators"]
        direction LR
        replay[replay/engine.py<br/>bleak GATT + mutations]
        integrations[integrations/<br/>driver / HA / MQTT]
        pcap[export_pcap.py]
    end

    nrf --> parser
    pl --> parser
    probe --> parser
    parser --> daemon
    daemon --> db
    db --> sqlite
    db <--> analysis
    db <--> io
    io --> ui
    db --> outputs
    io --> replay
    io --> integrations
```

The dotted-line invariant: **SQLite is the only durable state.** WebSocket
broadcasts, in-memory daemon caches, and the alias resolution layer are all
optimisations that can be rebuilt from the DB.

## Process model

bt-spy runs as a single Python process (`bt-spy serve` → uvicorn → FastAPI app).
Inside that process:

```mermaid
flowchart LR
    subgraph proc["bt-spy serve process"]
        FAPI[FastAPI event loop]
        DAEMON[CaptureDaemon<br/>threading.Thread]
        SUB[Source subprocess<br/>nrfutil ble-sniffer<br/>OR PL CLI]

        FAPI <-->|start/stop| DAEMON
        DAEMON -->|spawns| SUB
        SUB -->|writes pcap or pklg| FILE[(temp pcap/pklg)]
        DAEMON -->|tails| FILE
    end
    SUB -.->|stdin closed on stop| SUB
    DAEMON -->|broadcast queue| FAPI
    FAPI -->|WebSocket| BROWSER([Browser])
```

Key behaviours:

- **Capture in a thread, not the event loop.** Reading from a subprocess pipe is
  blocking I/O; doing it in the event loop would stall the WebSocket and REST
  handlers.
- **Cleanup via `_cleanup` callable.** When you click Stop, `daemon.stop()`
  sets `_stop`, invokes `_cleanup()` (which terminates the source subprocess
  and unlinks any tempfile), then joins the thread. This is why old "stuck
  capture" bugs are fixed — a blocked read on a dead subprocess unblocks the
  moment we kill the process.
- **Single MCP server, single REST server, single DB.** No coordination
  protocol needed because they're all in-process talking to the same SQLite.

## Capture sources & how they fit a uniform pipeline

```mermaid
flowchart TB
    subgraph nrf["nrf_sniffer source"]
        direction TB
        n1[find nrfutil 8.x binary<br/>via shutil.which]
        n2[spawn `nrfutil ble-sniffer sniff`<br/>--output-pcap-file tempfile.pcap]
        n3[iter_pcap_classic_tail<br/>big-endian detect + linktype 272]
        n1 --> n2 --> n3
    end

    subgraph pkl["pklg_tail source"]
        direction TB
        p1[user enters PL save path<br/>auto-detected via lsof -F nfa]
        p2[iter_pklg_tail<br/>Apple record format: ts + type + payload]
        p1 --> p2
    end

    subgraph synth["probe (synthetic)"]
        direction TB
        s1[bleak BleakClient.connect]
        s2[walk services + characteristics]
        s3[emit synthetic ATT frames<br/>to subscriber callback]
        s1 --> s2 --> s3
    end

    nrf --> FRAMES{{Frame iterator}}
    pkl --> FRAMES
    synth --> FRAMES
    FRAMES --> DECODER[decode_frame<br/>linktype-based routing]
    DECODER --> WRITE[db.insert_packet]
    DECODER --> BCAST[subscriber broadcast<br/>WS events]
```

Adding a new source is one function: anything yielding `parser.Frame` objects
can plug into `CaptureDaemon._start_source`. See [extending.md](extending.md).

## Decode routing

`decode_frame` dispatches based on the pcap linktype:

```mermaid
flowchart LR
    FRAME[Frame] --> CHK{linktype?}
    CHK -- 187/201 HCI_H4 --> HCI[decode_hci<br/>scapy HCI/L2CAP/ATT]
    CHK -- 251 BTLE_LL --> BTLE[decode_btle<br/>scapy BTLE]
    CHK -- 256 BTLE_LL_PHDR --> PHDR[strip 10 bytes<br/>then decode_btle]
    CHK -- 272 NORDIC_BLE --> NRD[strip 17-byte Nordic prefix<br/>extract channel/RSSI<br/>then decode_btle]
    HCI --> OUT[DecodedPacket]
    BTLE --> OUT
    PHDR --> OUT
    NRD --> OUT
```

The decoder pulls these fields when present:

| Field | Where it comes from |
| --- | --- |
| `handle` | ATT handle (GATT-level, distinct from connection handle) |
| `opcode` | ATT op (write/read/notify/indicate) |
| `payload` | The bytes that get encoded/decoded by your protocol entries |
| `conn_handle` | HCI ACL link-layer connection handle (proxy for "which device" on connected traffic) |
| `device_addr` | BD_ADDR from advertising AdvA / HCI connection-complete / probe target |
| `device_name` | Local name from advertising AD records (only if device broadcasts it) |

## Reverse-engineering workflow

```mermaid
flowchart TB
    A[Start capture] --> B[Tag actions with markers<br/>'tap_on', 'slide_brightness']
    B --> C[Stop capture]
    C --> D{Compare}
    D --> D1[diff session vs baseline]
    D --> D2[marker-range diff inside session]
    D1 --> E[Find handle + payload<br/>that's new]
    D2 --> E
    E --> F[Click 'Find checksum'<br/>on handle summary]
    F --> G[Replay with mutations<br/>set_byte / xor / inc / sweep]
    G --> H{Device responds<br/>as predicted?}
    H -- Yes --> I[Save protocol_entry<br/>encoder + decoder + name]
    H -- No --> E
    I --> J[Scaffold:<br/>driver / HA / MQTT bridge]
```

This loop is exactly what the UI and MCP tools are wired around. The "save
protocol_entry → scaffold" handoff is the moment the RE work turns into shippable
code.

## Storage model

```mermaid
erDiagram
    sessions ||--o{ packets : contains
    sessions ||--o{ annotations : has
    sessions ||--o{ replays : "may be source of"
    packets }o--o{ annotations : "covered by (range)"
    protocol_entries }o--|| device_aliases : "names device for"
    device_aliases ||--o{ packets : "names device_addr of"
    device_ltks ||--|| device_aliases : "decrypts traffic from"

    sessions {
        int id PK
        string label
        string capture_source
        real started_at
        real ended_at
    }
    packets {
        int id PK
        int session_id FK
        real ts
        string direction
        string pdu_type
        int handle
        int conn_handle
        string device_addr
        bytes payload
        bytes raw
        json decoded
    }
    annotations {
        int id PK
        int session_id FK
        int packet_id_start
        int packet_id_end
        string label
    }
    protocol_entries {
        int id PK
        string device_name
        int handle
        string direction
        string name
        string char_uuid
        string structure_json
        string encoder_py
        string decoder_py
    }
    device_aliases {
        string device_addr PK
        string name
        string source
    }
    device_ltks {
        string device_addr PK
        string ltk_hex
    }
    replays {
        int id PK
        int session_id FK
        string target_mac
        string sent_json
        string response_json
    }
```

Full schema reference: [data-model.md](data-model.md).

## Replay engine

```mermaid
sequenceDiagram
    participant UI as Web UI
    participant API as REST API
    participant Engine as Replay engine
    participant Bleak as bleak BleakClient
    participant Device as BLE peripheral
    participant DB

    UI->>API: POST /api/replay {target, steps}
    API->>Engine: run_replay(steps)
    Engine->>Bleak: BleakScanner.find_device_by_name (if name)
    Engine->>Bleak: BleakClient.connect()
    loop For each step
        Engine->>Engine: apply_mutation(payload, strategy)
        Engine->>Bleak: write_gatt_char(uuid, mutated_payload)
        Bleak->>Device: GATT write
        Device-->>Bleak: ack / notify
        Bleak-->>Engine: write_ack + accumulated notifies
    end
    Engine->>DB: record_replay(sent, observations, status)
    Engine-->>API: ReplayResult
    API-->>UI: JSON
```

Mutation strategies are pluggable via `@register_mutation(name)`. Out of the
box: `set_byte`, `xor_byte`, `increment_byte`, `replace`. Plus the **sweep**
variant which generates a strategy invocation per value in a range.

## MCP integration (Claude as the co-pilot)

```mermaid
flowchart LR
    CLAUDE([Claude]) <-->|stdio JSON-RPC| MCP[mcp/server.py]
    MCP <-->|in-process function calls| DB[(SQLite)]
    MCP -->|REST self-calls| REST[FastAPI app]
    REST --> DB

    subgraph tools["MCP tools exposed"]
        T1[list_sessions]
        T2[get_packets]
        T3[diff_sessions]
        T4[handle_summary]
        T5[infer_structure]
        T6[add_annotation]
        T7[upsert_protocol_entry]
        T8[replay]
        T9[ble_scan]
        T10[ble_probe]
        T11[start_capture]
        T12[stop_capture]
        T13[import_pklg]
        T14[export_driver]
        T15[scaffold_ha_integration]
        T16[vocabulary]
    end

    MCP --> tools
```

Claude doesn't *replace* you — it accelerates the boring parts: pattern-finding
in payloads, structure hypotheses, replay configuration, scaffold generation.
You still drive the "what should I try next" decisions.

## Output generators

```mermaid
flowchart LR
    PE[protocol_entries] --> EXP{Export}

    EXP -->|export_driver| DRV[drivers/devicename.py<br/>standalone bleak class]
    EXP -->|scaffold_ha| HA[custom_components/<br/>full HA integration]
    EXP -->|mqtt bridge| MQTT[long-running bridge<br/>HA MQTT discovery]

    SESS[sessions + packets] -->|export_pcap| PCAP[.pcap file<br/>Wireshark-compatible]
```

Driver export is the foundation — both the HA scaffold and the MQTT bridge
*import* the generated driver so they stay in sync as you refine encoders.

## Threading + concurrency

bt-spy runs three concurrent contexts:

| Context | What runs in it | Lifetime |
| --- | --- | --- |
| FastAPI event loop | REST handlers, WS clients, MCP tool dispatch | bt-spy serve uptime |
| CaptureDaemon thread | source subprocess + pcap/pklg tailer + decode + DB write | One per capture session |
| bleak event loop | replay + probe + scan (async, runs on FastAPI loop) | Per request |

Concurrency-safety relies on SQLite's WAL mode: readers (REST handlers,
analysis) don't block the capture daemon writer. The only place we serialize
explicitly is the daemon's `db.insert_packet` — sqlite3's default isolation
handles the rest.

## File layout

```
src/bt_spy/
├── cli.py                      # Typer CLI entry
├── config.py                   # Settings (env-overridable)
├── db.py                       # SQLite schema, migrations, queries
├── ble_host.py                 # bleak scan + probe
├── export_pcap.py              # Wireshark-compatible export
│
├── capture/
│   ├── daemon.py               # CaptureDaemon (source-agnostic loop)
│   ├── extcap.py               # nrfutil + legacy Wireshark wrapper
│   ├── packetlogger.py         # Apple PL .pklg parser + tail
│   └── parser.py               # pcap/pcap-ng readers + decoders
│
├── analysis/
│   ├── decoder.py              # built-in + snippet decoders
│   ├── diff.py                 # handle summary + structure inference
│   └── checksum.py             # CRC/sum/xor brute force
│
├── replay/
│   └── engine.py               # bleak GATT writes + mutation strategies
│
├── integrations/
│   ├── vocabulary.py           # canonical entry name → HA platform
│   ├── driver.py               # standalone Python driver export
│   ├── homeassistant.py        # custom_component scaffolder
│   └── mqtt_bridge.py          # long-running MQTT bridge
│
├── firmware/
│   └── flasher.py              # Legacy zip-download path (kept for fallback)
│
├── decoders/                   # Drop-in built-in decoders
│   ├── example_battery.py
│   └── sig_standard.py
│
├── api/
│   └── server.py               # FastAPI app: REST, WS, SSE, file upload
│
├── mcp/
│   └── server.py               # MCP stdio server for Claude
│
└── web/
    ├── templates/index.html    # Single-page UI
    └── static/{app.js, style.css}
```

## When to read what

| Want to understand… | Read |
| --- | --- |
| Why decisions were made | [design.md](design.md) |
| What the data looks like | [data-model.md](data-model.md) |
| How to call from code | [api-reference.md](api-reference.md) |
| How to add a decoder or capture source | [extending.md](extending.md) |
| What the user sees | [user-guide.md](user-guide.md) |
