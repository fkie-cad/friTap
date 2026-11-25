# Linux eBPF TLS fixture capture

This opt-in runtime attaches to one already-running local Linux PID. It
captures successful OpenSSL 3 `SSL_read`, `SSL_write`, `SSL_read_ex`, and
`SSL_write_ex` calls. Records use a connection identifier local to the
session. `.tap` records and callbacks leave unknown endpoints unset.
The native runtime reports the mapped OpenSSL ELF build ID and running
kernel release and the selected transport.

On Ubuntu 24.04, install a C compiler, make, Clang, bpftool, libbpf-dev, and
libelf-dev. The loader prefers BPF ring buffers and uses perf buffers when
the kernel lacks ring-buffer support. Both paths need BPF and uprobes. The
perf path supports Linux 5.4 and later with perf events and a BPF helper
that can read userspace memory. Neither object needs device BTF. Build on the target architecture with `make -C agent_ebpf`. friTap checks the active
Python scripts directory first and then `agent_ebpf/build` in the source
checkout. To use the binary with an installed friTap package, copy it into
the active Python environment's scripts directory.

```sh
make -C agent_ebpf
install agent_ebpf/build/fritap-ebpf-agent "$(env/bin/python -c 'import sysconfig; print(sysconfig.get_path("scripts"))')/"
sudo env/bin/fritap --backend ebpf --backend-readiness "$PID"
sudo env/bin/fritap --backend ebpf --protocol tls --tap fixture.tap "$PID"
```

Run the two friTap commands under the same authorized identity. PID-specific
readiness loads the capture object and opens and releases its
attachments with collection disabled. Successful preflight reports
`ready`. Startup repeats the checks before announcing that capture is
running. A target-free readiness report describes the environment and can
use the standalone helper in [dev/ebpf](../dev/ebpf/README.md).

```python
from friTap import FriTap

session = FriTap(str(pid)).backend("ebpf").on_data(handle_data).tap("fixture.tap").start()
session.wait()
```

The native stream starts with a readiness or stage error record. It encodes
plaintext as hexadecimal and ends with the number of records dropped.
For perf, the loader merges per-CPU samples by TLS call completion timestamp
and chunk order, using a bounded queue with a 100 ms reorder window.
Records that arrive out of order after delivery or exceed the queue capacity
count as loss. Perf overflow counters and notifications are reconciled per
CPU, including overflows that occur just before the producer stops. A positive loss count produces an incomplete-capture
diagnostic. Stopping or exiting the target detaches the probes and drains
queued records before friTap finalizes its outputs.

## Privileged fixture suite

From the macOS host, use `./dev/ebpf/test-lima.sh` to build and run the
suite end to end. See the [Lima helper instructions](../dev/ebpf/README.md)
for guest requirements and test selection.

Install OpenSSL development headers, the OpenSSL CLI, binutils, and pytest in
addition to the build dependencies. Use an editable friTap checkout and a
fresh Python environment. These commands install the Python package and
test dependencies without Frida. Run from the checkout on the Linux guest.

```sh
python3 -m venv env
env/bin/pip install --no-deps -e .
env/bin/pip install pytest pytest-timeout hexdump scapy watchdog psutil rich \
  textual platformdirs pydantic h11 hpack pylsqpack zstandard brotli cryptography
```

Build and install the native binary into that environment as above.

```sh
sudo env FRITAP_RUN_EBPF_TESTS=1 env/bin/python -m pytest -q -s tests/integration/ebpf
```

The harness verifies that the client and server map the same OpenSSL library
and prints its build ID and the kernel version. It builds a separate native
binary with a small ring buffer and test controls for attachment failure and
delayed draining.

The Ubuntu 24.04 arm64 Lima acceptance run used kernel
`6.8.0-149-generic` and OpenSSL build ID
`af9a5b86e0adcb55e9f5e959eb8178c71fe5ecfb`.

## Android

[Build and deploy the Android OpenSSL loader](../dev/ebpf/README.md#android-openssl-fixture)
and run the owned loopback fixture on a root-capable arm64 AVD. Device-side
readiness and capture run under the selected ADB shell identity.

## Plaintext PCAP

Use `-p` for plaintext PCAP or PCAPNG output.

```sh
sudo env/bin/fritap --backend ebpf -p fixture.pcap "$PID"
sudo env/bin/fritap --backend ebpf -p fixture.pcapng "$PID"
```

The standard PCAP writers use synthetic TCP endpoints in the 198.18.0.0/15
benchmarking range when the native record has no socket metadata. The tuple
identifies a stream within the capture.

Add `-f` to capture original wire packets using the standard local capture
worker. The wire capture covers the selected host interfaces. Add
`--loopback` to include loopback traffic.

```sh
sudo env/bin/fritap --backend ebpf -k mykeys.log -p wire.pcap -f "$PID"
```

When `-k` is present, the eBPF key-extraction stub reports that TLS key
extraction is currently unavailable. It leaves the requested keylog path
untouched while packet capture proceeds.

A single successful call can emit up to 1 MiB in 16 KiB chunks. A buffer
overflow, unreadable chunk, or call beyond the capture limit is reported
as an incomplete capture.
