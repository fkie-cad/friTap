# Offline quickstart (5 minutes)

Already have a packet capture on disk? You don't need a live target to use
friTap. This quickstart turns a `pcap` + its TLS keys into a friTap `.tap`, then
analyzes and replays it — three commands, start to finish.

We'll use the sample capture that ships with the repo: **`chrome.pcap`** (a
Chrome session) and its key log **`chromekeys.log`**, both at the repo root.

!!! warning "Requires Wireshark / tshark ≥ 4.x for the conversion step"
    The first command (`--from-pcap`) uses **tshark** to decrypt the capture, and
    tshark is **not** installed with friTap. Install Wireshark
    (`brew install wireshark`, `apt install tshark`, or
    [wireshark.org](https://www.wireshark.org/)). If tshark is not on your `PATH`
    (common on macOS / Windows), add `--tshark-path /path/to/tshark`.

    **No tshark handy?** No problem — skip step 1 and use the committed
    `capture_20260507_153933.tap` directly in steps 2 and 3 (substitute that
    filename for `out.tap`). Steps 2 and 3 do **not** need tshark.

---

## Step 1 — Convert the pcap to a `.tap`

```bash
# requires Wireshark/tshark ≥ 4.x
fritap --from-pcap chrome.pcap --keylog chromekeys.log --tap out.tap
```

friTap drives tshark to decrypt the TLS/QUIC traffic, reconstructs the flows with
its own protocol parsers, and writes `out.tap`. You'll see a short summary:

```text
Wrote out.tap
  flows:             42
  decrypted packets: 318
  streams:           12
```

That's the whole conversion. The `.tap` is now a self-contained, decrypted
record you can analyze and replay anywhere — no keys or tshark needed from here.

---

## Step 2 — Analyze it

```bash
fritap analyze out.tap --report table
```

This runs friTap's analyzers over the flows and prints a findings table
(credentials, IOCs, protobuf, …). It's read-only and passive.

!!! tip "No tshark? Start here"
    Steps 2 and 3 work on any `.tap`, including the committed sample:
    ```bash
    fritap analyze capture_20260507_153933.tap --report table
    ```

---

## Step 3 — Replay it in the TUI

```bash
fritap -r out.tap
```

This opens the [replay TUI](tui.md): browse every flow, inspect requests and
responses, filter Wireshark-style, and export. It's the most fun way to explore
what a capture actually contained.

---

## That's it 🎉

In three commands you went from a raw capture to a fully decrypted, searchable,
replayable record — entirely offline. From here:

- **Go deeper on conversion:** [Offline pcap → .tap](../advanced/offline-pcap-to-tap.md)
  covers keyless captures, manifest sidecars, custom ports, exit codes, and the
  `pcap_to_tap()` Python API.
- **Hunt for findings:** [Traffic analysis](../advanced/traffic-analysis.md) —
  write your own analyzers and wire findings into CI.
- **Master the TUI:** [Replay TUI](tui.md) — keybindings, filters, and export.
