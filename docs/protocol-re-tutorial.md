# Reverse-engineering a BLE protocol — a worked example

Suppose you have a "MiSmartLight" smart bulb and a vendor app that controls it.
You want a Python script that does the same thing. Here's the full loop.

## 0. Before you start

- Flash your dongle (`bt-spy flash`).
- Put the dongle and the bulb close together — within a metre.
- Have your phone with the vendor app ready.

The sniffer can only listen to **one BLE connection at a time** (it locks onto
a connection request and follows that connection's channel hopping). When you
start a capture, the dongle is sniffing advertisements and waiting for a
connection — so don't connect from the app until *after* you start the capture.

## 1. Baseline: idle traffic

```bash
bt-spy capture baseline --notes "bulb idle, app not connected"
```

Let it run ~30 seconds. You'll see mostly advertising packets (the bulb shouting
"I exist!" every few hundred ms). Ctrl-C to stop.

## 2. Capture an action: turn the bulb on

```bash
bt-spy capture turn_on --notes "opened vendor app, tapped Power On"
```

Then on your phone: open the app, connect to the bulb, tap Power On. Wait a
beat. Ctrl-C.

Open the web UI (`bt-spy serve`) → Sessions → click your `turn_on` session →
**Summary**. You'll see something like:

| handle | dir                    | n   | unique | avg len | byte variability    |
| ------ | ---------------------- | --- | ------ | ------- | ------------------- |
| 36     | central->peripheral    | 3   | 2      | 4.0     | 0.00 0.66 0.00 0.00 |
| 38     | peripheral->central    | 4   | 4      | 6.0     | 0.75 0.50 0.25 0.0…|

Read this: handle 36 received 3 writes, 2 unique. Byte 1 varies; bytes 0, 2, 3
are constant.

## 3. Diff: what's *new* compared to baseline?

In the UI: Diff tab → baseline=1, candidate=2 → Diff.

In the CLI:

```bash
bt-spy diff 1 2
```

You'll see only the packets that didn't appear in baseline. With idle baseline
removed, the signal is usually 2–10 unique packets — these are the command.

In our example you might see writes to handle 36 with payloads:

```
01 00 ff 7e
01 01 ff 7e
```

Read those bytes: `01` constant, `00`/`01` differ (might be off/on), `ff` and
`7e` constant. Hypothesis:

- byte 0 = command (0x01 = power)
- byte 1 = value (0 = off, 1 = on)
- bytes 2–3 = unknown, probably tail/checksum

## 4. Annotate

In the UI, find one of those packets in the session view. Click → annotate:

> label: power_command
>
> notes: writes to handle 36; payload[0]=0x01, payload[1]=on/off, payload[2..3]=?

Or via MCP (let Claude do it):

> Mark packets 12 and 14 of session 2 as "power_command".

## 5. Replay (confirm)

Send the "off" payload yourself and see what happens. Either from the UI's
Replay tab or:

```bash
bt-spy replay "MiSmartLight" \
  '[{"handle":36,"payload_hex":"0100ff7e","write_with_response":false}]'
```

Bulb should turn off. If it does — your hypothesis is confirmed.

## 6. Probe with mutations

What if you set byte 1 to 0x02? 0xff? Let's find out:

```bash
for v in 00 01 02 ff; do
  bt-spy replay "MiSmartLight" \
    "[{\"handle\":36,\"payload_hex\":\"01${v}ff7e\",\"write_with_response\":false}]"
  sleep 0.5
done
```

If the bulb behaves identically for all non-zero values: byte 1 is boolean,
not numeric. If 0x80 gives half-brightness: it's a brightness byte, and 0/1
were just the app sending the extreme values.

You can also do this from Claude — the MCP server's `replay` tool takes a
`mutation` field, so Claude can sweep mutations and report what happened.

## 7. Discover bytes 2–3

The two trailing bytes are constant in your captures but might be a checksum or
length field. Mutate them and watch:

```bash
bt-spy replay "MiSmartLight" \
  '[{"handle":36,"payload_hex":"0100007e","write_with_response":false}]'
```

If the bulb ignores the write (no state change, no error notify) — checksum.
If it works regardless — padding. If a notify comes back with an error opcode
(0x01 = ATT_ERROR_RSP) — same.

If checksum, try common variants:
- sum of bytes 0..1 → compare to byte 2
- XOR of bytes 0..1 → compare to byte 2
- CRC-8/CRC-16 against bytes 0..1

For our example, payloads were `01 00 ff 7e` and `01 01 ff 7e`. The constant
`ff 7e` across two payloads with one differing byte rules out a real checksum
(it'd differ too) — likely just a frame tail.

## 8. Save to protocol dictionary

UI: Protocol Dict tab → expand "Add / edit" → fill in:

- device_name: `MiSmartLight`
- handle: 36
- direction: `central->peripheral`
- name: `power_command`
- structure:
  ```json
  [{"offset":0,"length":1,"name":"cmd","value":1},
   {"offset":1,"length":1,"name":"on","encoding":"bool"},
   {"offset":2,"length":2,"name":"tail","value_hex":"ff7e"}]
  ```
- decoder snippet:
  ```python
  def decode(payload):
      assert payload[0] == 0x01 and payload[-2:] == b"\xff\x7e"
      return {"on": bool(payload[1])}
  ```

Save. Now `bt-spy` (and Claude) know this command going forward.

## 9. Repeat for every action

- baseline → capture an action → diff → annotate → replay-confirm → save entry.
- After a few actions you can start spotting structure across them (same prefix
  byte for the same kind of command, same tail bytes for all messages, etc.).
- After ~10 entries you have enough to build a clean Python wrapper.

## 10. Build the wrapper

The simplest version is a small bleak script:

```python
import asyncio
from bleak import BleakClient

ADDR = "5A7F1234-AAAA-..."  # CoreBluetooth UUID from bt-spy
CHAR = "0000fff1-0000-1000-8000-00805f9b34fb"

async def power(on: bool):
    async with BleakClient(ADDR) as c:
        await c.write_gatt_char(CHAR, bytes([0x01, int(on), 0xff, 0x7e]), response=False)

asyncio.run(power(True))
```

…and you're done. The whole point of bt-spy is to make the work *getting to that
script* tractable.

## When the protocol is harder

This worked-example assumes the bulb is unauthenticated and the payload is
plaintext. Some devices are noisier — they have:

- **Authentication handshake** — the first few writes are key exchange. You
  can replay them verbatim (since they're recorded) but won't be able to
  generate new sessions without understanding the auth. Often that's still
  enough for "I just want to control my own device."
- **Encrypted payloads** — same writes always produce different bytes. Look
  for the BLE LL link layer to be using LE Secure Connections. The sniffer
  can still capture (the OTA traffic) but you'd need the LTK to decrypt.
- **Counter or nonce bytes** — bytes that monotonically increase across
  messages. The `handle_summary` will flag them as high-variance. Often
  setting them to whatever the previous-observed value + 1 is enough to make
  the device accept your replays.

For the first two, bt-spy's diff/replay loop still helps a lot: even if you
can't reproduce, you can map "the user did X" → "these 6 packets flew" and
build a state machine of the protocol shape.

## A whole conversation with Claude

Once you have the MCP server wired up, sessions like this work:

> I captured session 5 of me sliding the brightness slider in the app. Session 3
> is the baseline. What handle is the brightness command going to, what does
> the payload encoding look like, and can you save a protocol entry?

Claude will:
1. Call `diff_sessions(3, 5)` → see only handle 36 writes are new.
2. Call `get_packets(5, handle=36)` → look at the payloads.
3. Notice byte 1 increases monotonically as slider moved.
4. Call `infer_structure(5, 36)` → naive segmentation confirms byte 1 is
   high-variance, others are constant.
5. Call `replay(target, [{handle:36, payload_hex: "01 80 ff 7e"}])` to confirm
   half-brightness.
6. Call `upsert_protocol_entry` with the structure + a decoder snippet.

You watch and approve. Done.
