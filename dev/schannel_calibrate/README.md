# Schannel x64 calibration tooling (dev-only)

Measures the **x64** ncryptsslp.dll memory-layout offsets for the `schannel`
profile in `friTap/memory_scanning/patterns.json`, so its
`arch.x64.calibrated:false` block can be populated on real hardware.

This directory is **developer tooling**. It is **not** part of the shipped `friTap`
package and is never imported by it — it runs standalone on a Windows x64 box.

> ## ⚠️ Reboot risk — this harness HOOKS lsass.exe
>
> The read-only mem-scan scanner (`friTap --memory-scan`, `agent/memory_scan_agent.ts`)
> only **reads** lsass memory (`PROCESS_VM_READ`) and is safe. **This calibration
> harness is different: `agent/calibrate.js` INSTRUMENTS lsass** — it hooks the
> seven `ncrypt!Ssl*` functions (`SslHashHandshake`, `SslGenerateMasterKey`,
> `SslGenerateSessionKeys`, `SslImportMasterKey`, `SslExpandTrafficKeys`, …) to get
> ground-truth secrets and confirm the struct offsets.
>
> Hooking crypto code inside lsass can **crash lsass, which forces a reboot** (this
> was observed repeatedly during the original research). Run it only on a
> **disposable / test VM** you can reboot, never on a machine you care about, and
> never in production. You will also need it running elevated (lsass is protected);
> if PPL/LSA protection is on, either the attach fails cleanly or you must disable
> protection on the test VM first.

## What each file does

| file | role |
|------|------|
| `agent/calibrate.js` | Frida agent. Hooks the ncrypt `Ssl*` functions in lsass, emits an oracle NSS keylog (JOB 1), and MEASURES the layout (JOB 2): the invariant needle pointer into ncryptsslp.dll, client_random reachability, and whether the hypothesised struct offsets hold. |
| `schannel_calibrate.py` | Driver. Attaches `calibrate.js` to lsass, collects the ground truth, writes the oracle keylog and a `calib.json` report with the derived measurements. |
| `emit_x64_offsets.py` | Offline. Turns `calib.json` into a paste-ready `arch.x64` block — **derived only from the measurements, never invented**. |
| `schannel_autocalibrate.py` | Offline. Derives the `session_cache` `session_id_at` offset from a `--dump-cache` window + the pcap's ServerHello session ids (`session-id` mode), and locates client randoms in a flat dump (`analyze` mode). |
| `frida_helpers.py` | Vendored frida attach / NSS-keylog helpers so this dir is self-contained. |
| `decrypt_pcap.py`, `minidump_reader.py`, `proc_mem.py` | Vendored offline helpers `schannel_autocalibrate.py` imports. |

## Prerequisites

```
pip install frida cryptography
```
Wireshark/tshark on `PATH` (for `schannel_autocalibrate.py`). A test VM you can reboot.

## Workflow

1. **Capture ground truth + layout** while TLS 1.2/1.3 traffic flows through lsass
   (e.g. drive `Invoke-WebRequest`/PowerShell HTTPS in another window):

   ```powershell
   python schannel_calibrate.py --name lsass --seconds 60 `
       --out calib.json --keylog oracle.keylog
   ```

   Watch the printed `=== derived SChannel layout ===` digest: the **needle
   candidates** ranked list should show a recurring pointer `-> ncryptsslp.dll+<rva>`,
   and **offset confirmation on x64** should report `tls12_master: CONFIRMED`.

2. **Render the x64 block** from the measurements:

   ```powershell
   python emit_x64_offsets.py --report calib.json --min-count 2
   ```

   This prints a JSON `{"x64": { … }}` block. It sets `"calibrated": true` **only**
   when at least one ncryptsslp.dll needle recurred (≥ `--min-count`) **and** the
   tls12 layout was confirmed; otherwise it warns and keeps `calibrated:false`.

3. **Paste into the profile.** Open `friTap/memory_scanning/patterns.json`,
   find the `schannel-win11-ncryptsslp` profile → `arch` → `x64`, and replace the
   `x64` block with the emitted one (keep the surrounding `arm64` block untouched).
   Concretely:
   - fill `arch.x64.needle.candidates` with the emitted `rva`/`note` entries,
   - set `arch.x64.tiers.tls12_master.{needle_at,master_at,master_len}` to the
     confirmed values, and
   - flip `arch.x64.calibrated` to `true`.

4. **(optional) session-cache offset.** To enable the direct
   `RSA Session-ID:<sid> Master-Key:<master>` correlator on x64, run the read-only
   `--dump-cache` scan, then:

   ```powershell
   python schannel_autocalibrate.py session-id `
       --cachedump schannel.cachedump.txt --pcap capture.pcap --write
   ```
   which finds `session_id_at` and flips `session_id_calibrated:true`.

## Do NOT invent offsets

The shipped profile keeps `arch.x64.calibrated:false` and an **empty** x64
needle-candidate list on purpose: with no needle, the x64 tls12/session-cache tiers
resolve nothing and no-op safely instead of emitting garbage. The **only** correct
way to populate x64 is to MEASURE it with this harness on real x64 hardware — never
hand-write RVAs or struct offsets. `emit_x64_offsets.py` enforces this: every value
it emits comes from `calib.json`, and a partial run stays `calibrated:false`.
