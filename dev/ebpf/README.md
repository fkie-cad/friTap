# Build and test the eBPF agent

From the host checkout, run the privileged fixture suite in the existing
Ubuntu Lima instance.

```sh
./dev/ebpf/test-lima.sh
./dev/ebpf/test-lima.sh -k full_capture
```

The script starts `lima-ubuntu-24.04`, copies the required sources to a fresh
writable guest directory under `/tmp`, creates a Frida-free Python environment,
builds and installs the native agent, then runs the suite with guest sudo.
It prints the guest path for inspecting the build and captures. The guest
stays running after the test. Set `FRITAP_LIMA_VM` to use another instance.

The guest needs a C compiler, Clang, bpftool, make, libbpf and libelf
development headers, the OpenSSL development headers and CLI, binutils,
Python 3 with venv support, and passwordless sudo. The running kernel must
support BPF and uprobes, plus ring buffers or perf events.

Build the native agent with `./dev/compile_agent.sh ebpf` in a Linux build
environment. The Makefile uses the build host architecture by default and links both
transport objects into one native loader. The build needs Linux UAPI headers. The default
and explicit `frida` targets build the Frida bundles.

For Android, use the self-contained arm64 build and ADB deployment steps
below. See the
[native agent documentation](../../agent_ebpf/README.md) for manual capture.

## Kernel readiness helper


The helper tests whether its execution identity can create a small BPF map and
load a minimal socket-filter program. It closes both descriptors immediately
and does not attach or pin anything. The results describe these two baseline
operations. For PID-specific preflight of the actual capture runtime, see
[Linux eBPF TLS fixture capture](../../agent_ebpf/README.md).

On Linux, build on the target with a C compiler and Linux userspace headers.

```sh
mkdir -p dev/ebpf/build
cc -Wall -Wextra -Werror -O2 dev/ebpf/check-kernel.c -o dev/ebpf/build/fritap-ebpf-check-kernel
fritap --backend ebpf --backend-readiness
```

Local Linux readiness automatically looks in the active Python scripts
directory and then `dev/ebpf/build`. If the helper is absent or cannot be
launched, friTap uses the environment's `bpftool` diagnostic. PID readiness
uses the native capture runtime to test the actual attachments.

For arm64 Android, set `ANDROID_CLANG` to the NDK's
`aarch64-linux-android24-clang` path and select an authorized test device.

```sh
"$ANDROID_CLANG" -Wall -Wextra -Werror -O2 -static dev/ebpf/check-kernel.c -o /tmp/fritap-check-kernel
adb -s "$SERIAL" push /tmp/fritap-check-kernel /data/local/tmp/fritap-check-kernel
adb -s "$SERIAL" shell chmod 700 /data/local/tmp/fritap-check-kernel
fritap --backend ebpf --backend-readiness --mobile "$SERIAL" \
  --ebpf-kernel-helper /data/local/tmp/fritap-check-kernel
adb -s "$SERIAL" shell rm /data/local/tmp/fritap-check-kernel
```

The Android result reflects the ADB shell's permissions. An enforcing device
can deny BPF operations even when the kernel implements them.

## Current support

| Capability | Local Linux | ADB-connected Android |
| --- | --- | --- |
| Platform discovery | Host OS, kernel and ABI | Selected serial, API level, kernel and ABI |
| Passive readiness | Execution UID, BPF policy and BTF visibility | ADB authorization and device availability |
| Active readiness | Optional `bpftool` or native helper | Optional target-side `bpftool` or native helper |
| Capture | OpenSSL 3 plaintext and local wire packets | OpenSSL 3 plaintext with the deployed arm64 loader |

`kernel_verified` means both native helper checks succeeded.
`permission_denied` means at least one operation was denied under the
identity that ran the helper. Check details retain the individual outcomes.
The readiness command never switches backends.

## Android OpenSSL fixture

Install both the Android 30 and Android 35 default arm64 SDK images, Android
Emulator, command-line tools, and an Android NDK. With the SDK on the usual macOS path, start a
dedicated AVD from the host checkout.

```sh
./dev/ebpf/run-android-avd.sh 35  # modern ring buffer, emulator-5570
./dev/ebpf/run-android-avd.sh 30  # Linux 5.4 perf buffer, emulator-5572
```

In another terminal, restart ADB as root on **that emulator** and check its
kernel. The tested default Android 35 arm64 image already provides suitable
ring-buffer and uprobe support. The stock Android 30 default image
contains kernel `5.4.86`. On that image the probes attach successfully,
but the legacy BPF helper fails when reading ARM64 userspace memory.
The perf acceptance fixture uses a dedicated kernel with that fix.

```sh
serial=emulator-5570
adb -s "$serial" wait-for-device
adb -s "$serial" root
adb -s "$serial" wait-for-device
env/bin/fritap --backend ebpf --mobile "$serial" --backend-readiness
```

Android readiness reports visible kernel configuration, BTF, and tracefs
evidence. Capture requires kernel 5.4 or later. PID-specific readiness probes
ring-buffer support, loads the selected object, opens the event buffers, and
tests the attachments under the same ADB identity as capture.

### Build and deploy the loader

On an arm64 Linux build host with a writable copy of the checkout, run
`dev/ebpf/build-android.sh`. This links a self-contained arm64 ELF against
static libbpf, libelf, zlib, and zstd. Both transport objects are embedded.
The same loader works with either emulator and does not need device BTF.

```sh
# In the arm64 Linux build environment:
./dev/ebpf/build-android.sh
# Back on the host after copying the built ELF from the build environment:
adb -s "$serial" push agent_ebpf/build/android-arm64/fritap-ebpf-agent /data/local/tmp/
adb -s "$serial" shell chmod 0755 /data/local/tmp/fritap-ebpf-agent
```

With a known Android PID using a dynamically linked OpenSSL 3 library:

```sh
env/bin/fritap --backend ebpf --mobile "$serial" --backend-readiness "$PID"
env/bin/fritap --backend ebpf --mobile "$serial" -p android.pcap "$PID"
```

This workflow was verified on `emulator-5570` with SELinux enforcing, kernel
`6.6.30-android15-8-gdd9c02ccfe27-ab11987101-4k`, and OpenSSL 3.0.18
build ID `da3b287091d1688640f4548c55099659847617c3`.

The loader validates the mapped ELF architecture, GNU build ID,
`OPENSSL_3.0.0` version definition, and required exports. Android input supports
plaintext PCAP, TAP, JSON files and Python callbacks. Wire-packet capture
(`-f`) is currently local only.

### Run the Android loopback tests

Use an OpenSSL 3 source tree. Cross-build shared libraries with the Android
NDK and with GNU build IDs enabled. For example, from a new OpenSSL build
directory on a Mac with the NDK installed:

```sh
export ANDROID_NDK_ROOT=/path/to/Android/sdk/ndk/version
export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
perl /path/to/openssl-source/Configure android-arm64 -D__ANDROID_API__=24 no-tests
make -j8 build_libs LDFLAGS=-Wl,--build-id=sha1
```

From the friTap checkout, compile both fixture programs against that build and
run the tests on the host.

```sh
./dev/ebpf/build-android-fixture.sh /path/to/openssl-source /path/to/openssl-build
FRITAP_ANDROID_EBPF_SERIAL="$serial" FRITAP_ANDROID_EBPF_FIXTURE=/path/to/openssl-build \
  env/bin/python -m pytest -q -s tests/integration/ebpf/test_android.py
```

Run the perf acceptance suite on the Android 30 emulator with
`FRITAP_ANDROID_EBPF_TRANSPORT=perf`. To include attachment rollback and
overflow, build and deploy the test loader, then set
`FRITAP_ANDROID_EBPF_TEST_CONTROLS=1`. The overflow case pauses the reader
while the owned fixture fills real per-CPU perf buffers. On
`5.4.86-fritap-perf-fixture`, with SELinux enforcing and device BTF absent,
all five tests passed. The induced overflow reported 22 lost records and
raised the incomplete-capture diagnostic.

```sh
# On the arm64 Linux build host:
make -C agent_ebpf BUILD=build/android-test ARCH=arm64 \
  LOADER_FLAGS="-static -DTEST_CONTROLS" LOADER_LIBS="-lbpf -lelf -lz -lzstd"
# After deploying that loader to the Android 30 emulator:
FRITAP_ANDROID_EBPF_SERIAL=emulator-5572 FRITAP_ANDROID_EBPF_FIXTURE=/path/to/openssl-build \
  FRITAP_ANDROID_EBPF_TRANSPORT=perf FRITAP_ANDROID_EBPF_TEST_CONTROLS=1 \
  env/bin/python -m pytest -q -s tests/integration/ebpf/test_android.py
```

### Rebuild the Android 5.4 fixture kernel

The dedicated image boots the stock Android 30 userspace with a kernel
rebuilt from the SDK image's source revision. The fixture patch routes
userspace addresses from the legacy helper to the existing
`probe_user_read()` implementation. The kernel's BPF security checks and the
image's SELinux policy still apply. The virtual-device drivers are built in
so boot and ADB can run independently of the SDK kernel's module ABI.
[Android kernel source revision](https://android.googlesource.com/kernel/common/+/ae78026f427c6692765ce1c2996d0a9cb6e486ef)
[Goldfish driver source revision](https://android.googlesource.com/kernel/common-modules/virtual-device/+/1366852424dade6356d73561385fd64d48698032)

Copy the stock API 30 default arm64 `kernel-ranchu` to an arm64 Linux build
host with Clang, LLD, and the Linux kernel build dependencies. The following
commands run from the kernel source tree at the revision above.
`virtual_device` points to a clone of the linked driver repository and
`fritap_repo` points to the friTap checkout.

```sh
scripts/extract-ikconfig "$stock_kernel" > .config
git apply "$fritap_repo/dev/ebpf/android54-userspace-read.patch"
scripts/config --disable LOCALVERSION_AUTO --enable LTO_NONE --disable LTO_CLANG \
  --disable CFI_CLANG --disable DEBUG_INFO --disable TRIM_UNUSED_KSYMS
scripts/config --enable VIRTIO_MMIO --enable VIRTIO_PCI --enable VIRTIO_BLK \
  --enable VIRTIO_CONSOLE --enable VIRTIO_NET --enable VIRTIO_INPUT --enable HW_RANDOM_VIRTIO
mkdir -p drivers/test-goldfish
git -C "$virtual_device" archive 1366852424dade6356d73561385fd64d48698032 goldfish_drivers uapi |
  tar -x -C drivers/test-goldfish
sed -i -e 's/^obj-m /obj-y /' -e 's|^LINUXINCLUDE .*|ccflags-y += -I$(src)/../uapi|' \
  drivers/test-goldfish/goldfish_drivers/Kbuild
sed -i -E 's/^#ifdef (CONFIG_(HW_RANDOM_VIRTIO|VIRTIO_(BLK|CONSOLE|INPUT|MMIO|NET|PCI)))$/#if !defined(\1) \&\& !defined(\1_MODULE)/' \
  drivers/test-goldfish/goldfish_drivers/defconfig_test.h
printf '\nobj-y += test-goldfish/goldfish_drivers/\n' >> drivers/Makefile
make ARCH=arm64 CC=clang LD=ld.lld CLANG_FLAGS= LOCALVERSION=-fritap-perf-fixture olddefconfig
make -j4 ARCH=arm64 CC=clang LD=ld.lld CLANG_FLAGS= LOCALVERSION=-fritap-perf-fixture Image.gz
```

Copy `arch/arm64/boot/Image.gz` to the emulator host. Start the dedicated
AVD with the rebuilt kernel and use the Android 30 serial in the acceptance
commands above.

```sh
FRITAP_ANDROID_TEST_KERNEL=/path/to/Image.gz ./dev/ebpf/run-android-avd.sh 30
```
