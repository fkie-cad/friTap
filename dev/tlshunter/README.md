# tlshunter

Read-only Android socket-holder diagnostics with Python 3.9+ and ADB.

```sh
python dev/tlshunter --device SERIAL --user 0 --package org.example.app
```

Repeat `--package` to inspect an explicitly selected worker package. Use
`--su` if the selected device already supports `su 0` and the shell cannot
read the relevant process metadata. Keep the device idle until the stderr
cue, then reproduce the action. Stdout contains JSON Lines. As a library,
import `Config`, `observe`, and `summarize` from `dev.tlshunter`.

Socket endpoints use the address representation from Android's proc tables
and hexadecimal ports. Socket rows identify observed FD holders. They can
miss short-lived sockets and cannot establish who sent on an already-open or
shared socket. Package association uses full UID and exact package or
colon-suffix process names. Custom process names and isolated services may
require additional Android runtime evidence. Library hints cover named ELF
mappings visible in proc maps. UI hints depend on the Android build's dumpsys
format. Missing evidence leaves attribution unresolved.

For an owned fixture, record device-monotonic handshake time and the
host-monotonic time of candidate delivery. Compare them only with a known
clock offset interval. `lead_time_bounds` propagates that interval. Compare
both bounds against independently measured readiness latency. A range that
straddles the readiness time leaves the result inconclusive.

## Owned delegation fixture

Build the client and worker debug APKs from `dev/fixtures/attribution_app`
with `gradle :delegation:assembleClientDebug :delegation:assembleWorkerDebug`.
Install both APKs on a disposable Android emulator, worker first. Run
`python -m dev.tlshunter.fixture_server --cert SERVER_CERT --key SERVER_KEY`
on the emulator host. Use a certificate with an IP SAN for `10.0.2.2`
issued by a test CA trusted by the emulator's user profile. The fixture
uses the Android debug trust configuration and still validates the server
name. The server logs accepted request IDs independently.

Start tlshunter with both `com.fritap.delegation.client` and
`com.fritap.delegation.worker` selected. After the interaction cue, run:

```sh
adb -s SERIAL shell am start -n com.fritap.delegation.client/com.fritap.delegation.Driver \
  --es id trial1 --es mode delegate --ei delay_ms 2000
adb -s SERIAL logcat -d -s TLSHUNTER_FIXTURE:I -v raw
```

Use a distinct ID each run. Modes are `direct`, `local`, `delegate`,
`control`, and `ui`. The control mode sends a Binder message without
networking. The UI mode opens the worker app without networking. Compare
zero delay against a deliberate pre-handshake delay. The fixture only
contacts the emulator host's loopback service.

For an offline Binder check, export the result of `binder.sql` as CSV
from a Perfetto trace that already contains Binder events. Then run:

```sh
python -m dev.tlshunter.offline binder binder.csv \
  --process com.fritap.delegation.client \
  --process com.fritap.delegation.worker:worker
```

Process IDs inside the trace are trace-local UPIDs. Use them to
distinguish lifetimes within that trace. The output preserves the trace
clock and leaves action attribution unresolved. Do not join trace and
observer records by PID alone.

Run `python -m dev.tlshunter.offline timing trials.jsonl` with one object per
trial. Each object takes `id`, `candidate_host_ns`, `handshake_device_ns`,
`clock_host_before_ns`, `clock_host_after_ns`, `clock_device_ns`, and
`readiness_ns`. Sample the same device clock used by the handshake marker
within the host before/after bracket. Account for clock sample resolution
and repeat calibration around the trial. Use null for a missing candidate
or handshake marker. The result compares remaining lead time against the
independently measured readiness latency.

`python -m dev.tlshunter.offline clock --device SERIAL` produces a host
bracket around Android boot time from `/proc/uptime`. Include its
`clock_resolution_ns` in the trial record. Recalibrate if the device was
suspended or rebooted. Use the host time at which the first candidate JSON
line was received, including any observer and transport latency.

To avoid changing the emulator's CA store, build the debug APKs with
`-PfixtureCaResources=/absolute/path/to/res`. Provide
`xml/fixture_local_trust.xml` in that resource directory and point its
trust anchors at the test certificate in `raw/`. Keep the private key
outside the resource directory. This build setting only applies to debug
APKs.
