#!/usr/bin/env python3

"""
Configuration dataclasses for friTap.

Replaces the 25+ parameter SSL_Logger constructor with structured,
validated configuration objects.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .backends.base import BackendName


class UnsupportedProtocolBackendError(ValueError):
    """Raised when a protocol does not support the selected backend."""
    pass


@dataclass
class DeviceConfig:
    """Configuration for target device connection."""
    device_id: Optional[str] = None  # Frida device ID (from TUI enumeration)
    mobile: bool | str = False
    host: Optional[str] = None
    spawn: bool = False
    enable_spawn_gating: bool = False
    spawn_gating_all: bool = False
    enable_child_gating: bool = False
    timeout: Optional[int] = None
    # Upper bound (seconds) for the agent's blocking ``script.load()``. Without
    # it a wedged agent hangs the session silently. ``0`` disables the bound.
    script_load_timeout: float = 20.0


@dataclass
class OutputConfig:
    """Configuration for output destinations and formats."""
    pcap: Optional[str] = None
    keylog: Optional[str] = None
    json_output: Optional[str] = None
    output_format: str = "auto"
    live: bool = False
    live_mode: str = ""  # "", "wireshark", "live_pcapng"
    verbose: bool = False
    full_capture: bool = False
    socket_trace: bool | str = False
    # --owner-capture (Android/Linux). Delegate full capture to the AppTap library
    # to acquire an *app-scoped* pcap (kernel UID-scoped: NFLOG where supported,
    # else a socket-table filter) instead of capturing the whole device and
    # post-filtering via the Frida socket trace. owner_strict / owner_no_dns narrow
    # the capture breadth; owner_nflog_group selects the Tier-2 NFLOG group.
    owner_capture: bool = False
    owner_strict: bool = False
    owner_no_dns: bool = False
    owner_nflog_group: int = 30
    filter_expression: Optional[str] = None  # Wireshark-like display filter
    # Drop frida/adb infrastructure traffic (ports 5037/5555/27042/27043) by default
    filter_infrastructure: bool = True
    # Include loopback/localhost traffic (e.g. a client talking to a local server,
    # Firefox NSS IPC). OFF by default; opt-in via --loopback, which makes a full
    # capture (-f) also sniff the loopback adapter and the pipeline keep loopback traffic.
    include_loopback: bool = False
    # Auto-relabel a Windows SChannel/lsass keylog by trial decryption against the
    # full capture at teardown (fixes TLS 1.3 label swaps + ??? client_randoms so the
    # keylog loads directly in Wireshark). ON by default; disable with --no-auto-relabel.
    auto_relabel: bool = True
    # A helper session that contributes to ANOTHER session's outputs: the Windows
    # LSASS worker (``hook_lsass`` in friTap.py) shares the target session's -p,
    # -k and --json paths. Its JSON session_info is recorded under
    # "auxiliary_sessions" so "session_info" stays the target session's.
    auxiliary_session: bool = False
    # Live passive-analysis ("scan") of observed traffic during capture.
    # ``scan`` is an analyzer spec (None disables; "all" / comma-list selects).
    scan: Optional[str] = None
    scan_report: str = "table"
    scan_report_out: Optional[str] = None
    scan_min_severity: str = "info"
    scan_min_confidence: float = 0.0
    scan_source: Optional[str] = None
    scan_category: Optional[str] = None
    scan_show_pii: bool = False
    # External analyzer references ("module" or "module:Class") to load for the
    # live scan, mirroring offline ``analyze --analyzer-path``. Repeatable.
    scan_analyzer_path: Optional[List[str]] = None


@dataclass
class HookingConfig:
    """Configuration for hooking strategies."""
    offsets: Optional[str] = None
    patterns: Optional[str] = None
    experimental: bool = False
    enable_default_fd: bool = False
    anti_root: bool = False
    payload_modification: bool = False
    library_scan: bool = False
    # QUIC plaintext capture boundary: "stream" (default lower-boundary
    # stream-level Readv hooks) or "app-api" (Boundary-4 decoded HTTP/3
    # headers; Chrome/Android Google QUICHE only).
    quic_capture_mode: str = "stream"
    # When True, the agent installs ONLY the Google QUICHE hooks and skips every
    # TLS-library hook (BoringSSL, Conscrypt, NSS, …), the Java hooks, OHTTP,
    # and the keylog scan-result hooks. Useful when the user only wants HTTP/3
    # capture: attach is dramatically lighter (no multi-megabyte Memory.scanSync
    # passes, no Java VM safepoint sync), which also helps fritap attach to a
    # target that is already in the middle of active QUIC traffic.
    quic_only: bool = False
    # When True, the agent skips the inline android_dlopen_ext loader hook. This
    # is the hook PairIP / anti-tamper runtimes detect and SIGSEGV on during a
    # spawn-time integrity scan (fkie-cad/friTap#64). Only already-loaded /
    # explicitly-selected TLS libraries are then hooked. The agent also auto-
    # skips it in spawn mode when an anti-tamper library is detected.
    no_loader_hook: bool = False
    # EXPERIMENTAL (Android). Watch android_dlopen_ext via a hardware breakpoint
    # (ARM64 debug registers, no linker code patch) instead of the inline
    # trampoline, so late-loaded TLS libs can be hooked on PairIP-protected apps
    # without tripping the anti-tamper scan. Unvalidated on-device; default OFF.
    stealth_loader: bool = False
    # --pairip-safe (Android; attach and spawn). Minimal, scan-free capture mode
    # for PairIP-protected apps: hook only a curated TLS-library allowlist
    # (libssl.so, libhttpengine.so, libjavacrypto.so, libconscrypt*,
    # libcommerce_http_client.so, offset-based libwebviewchromium.so; libunity.so
    # is opt-in via --offsets), resolved WITHOUT any Memory.scan (exports ->
    # symbols -> offsets). Skips the loader hook, WebView/Cronet pattern scan,
    # Java hooks, OHTTP and the library-scan pass — the broad footprint that trips
    # PairIP's periodic integrity check (an in-process SIGSEGV). Keys persist via
    # "blink" (hooks toggled so .text stays pristine between scans).
    # (fkie-cad/friTap#64). Default OFF.
    pairip_safe: bool = False
    # --probe. Dry-run diagnostic: the agent reports which platform branch it
    # selected and then stops BEFORE installing any hook. Exists because a
    # target that dies during instrumentation (fkie-cad/friTap#65) leaves the
    # user with no way to learn how far friTap got. Boolean on purpose — staged
    # verbosity levels would be a second, redundant knob next to -v/-do.
    probe: bool = False
    # --boringssl-anchor-only (Android arm64; debugging aid). Force friTap's
    # last-resort BoringSSL keylog tier (the "anchor locator") by skipping the
    # byte-pattern tier, so a fully-stripped BoringSSL lib (Chrome libchrome.so,
    # libhttpengine.so) routes straight to onAllKeylogTiersMissed -> tier 4. Lets
    # the anchor locator be exercised on modules a pattern would otherwise win.
    # Still honours --pairip-safe (tier 4 is a memory scan). Default OFF.
    force_anchor_locator: bool = False
    # Override which layer of the HTTP/3 egress-headers fallback chain the
    # agent actually attaches to. "auto" (default) keeps the winner-takes-all
    # logic: quiche-internal QuicSpdyStream::WriteHeaders preferred, then
    # net::QuicChromiumClientStream::WriteHeaders, then
    # quic::QuicSpdySession::WriteHeadersOnHeadersStream as a last-resort gQUIC
    # fallback. Set to "chrome-shim" or "session-level" to FORCE a fallback
    # layer for testing — useful for validating chain behavior on builds where
    # the quiche-internal layer still resolves. Only effective in app-api mode.
    quic_egress_headers_layer: str = "auto"
    # Generic memory-region key-scan target (--scan-keys-region). None disables
    # the scan. Passed through to the agent via config_batch.extensions.scan_region;
    # protocol-agnostic (the public scan engine and any private scan binding both
    # read it). See agent/shared/scan/.
    scan_keys_region: Optional[str] = None
    # Heap secret-scanner (--memory-scan / -ms). When True, friTap loads a
    # separate, independently-injected agent (friTap/fritap_memscan.js) that
    # recovers TLS secrets by scanning process heap memory instead of hooking
    # the TLS library. It is complementary to the normal capture: passed alone,
    # it is the ONLY thing loaded (the main TLS-hooking agent is skipped);
    # combined with -k/-p/-c it runs alongside them. memory_scan_patterns is the
    # optional -ms value: either a path to a user profile file that
    # overrides/extends the shipped friTap/memory_scanning/patterns.json,
    # OR a targeted engine name (boringssl | schannel | rc4) / profile id (F3).
    # The resolver (memory_scanning.loader.select_profiles) disambiguates by
    # resolution order — an existing file wins, then a known engine/id — so this
    # single field carries both meanings. memory_scan_interval is the poll
    # cadence (seconds) at which the host drives the scanner's scanOnce().
    memory_scan: bool = False
    memory_scan_patterns: Optional[str] = None
    memory_scan_interval: float = 2.0
    # Opt-in (--ms-emit-unconfirmed): also write memory-scan key candidates the
    # confirmation oracle could not verify (MTProto auth/E2E) to the keylog. OFF
    # by default; harmless offline since a wrong candidate matches no record.
    memory_scan_emit_unconfirmed: bool = False
    # RC4 memory-scanner oracles (--ms-rc4-known-plaintext / --ms-rc4-ciphertext).
    # There is no SSPI oracle on Android, so these inject a known-plaintext prefix
    # (an exact, zero-false-accept key test) and/or a ciphertext sample (for
    # trial-decrypt scoring) into the rc4 profile's params via
    # memory_scanning.loader.apply_rc4_param_overrides. Each accepts hex or plain
    # text; None (the default) leaves the profile untouched.
    memory_scan_rc4_known_plaintext: Optional[str] = None
    memory_scan_rc4_ciphertext: Optional[str] = None
    # Whether the main hooking agent (interception) runs at all. The TUI's
    # "Key Extraction Method" step sets this False for a memory-scan-only run;
    # see memory_scan_only(). The CLI leaves it True and relies on inference.
    intercept: bool = True
    encapsulated_protocols: Dict[str, bool] = field(
        default_factory=lambda: {"ohttp": True}
    )
    # Module names that should bypass the Cronet-split-topology suppression
    # check, even when friTap would otherwise treat them as covered by a
    # sibling library. Accepts literal names, prefixes (a value ending in '*'
    # is treated as a stem prefix), or regexes prefixed with "re:".
    force_scan_modules: List[str] = field(default_factory=list)

    @property
    def ohttp_enabled(self) -> bool:
        return self.encapsulated_protocols.get("ohttp", True)

    def __post_init__(self) -> None:
        env_value = os.environ.get("FRITAP_FORCE_SCAN")
        if env_value:
            extra = [item.strip() for item in env_value.split(",") if item.strip()]
            for item in extra:
                if item not in self.force_scan_modules:
                    self.force_scan_modules.append(item)


@dataclass
class FriTapConfig:
    """
    Top-level configuration for a friTap session.

    Usage:
        config = FriTapConfig(
            target="com.example.app",
            device=DeviceConfig(mobile=True, spawn=True),
            output=OutputConfig(pcap="capture.pcap", keylog="keys.log"),
        )
    """
    target: str
    # Original argv tokens for spawn mode (e.g. ["wine", "/p/My Game/app.exe"]).
    # Kept separate from `target` (which stays a single string for attach-by-name
    # / display) so spawn passes the real argv to device.spawn() instead of
    # re-splitting the joined string on spaces — which corrupts paths containing
    # spaces (issue #66 follow-up). None for attach mode / programmatic configs.
    target_argv: Optional[List[str]] = None
    device: DeviceConfig = field(default_factory=DeviceConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    hooking: HookingConfig = field(default_factory=HookingConfig)
    protocol: str = "tls"
    # Foundation F1 — multi-protocol selection. `protocols` is the CANONICAL
    # selection: an ordered, de-duplicated list of the protocols the user asked
    # for (e.g. ["tls", "rc4"]). `protocol` above is kept as the PRIMARY (first)
    # element so the many existing call sites that read a single `config.protocol`
    # string keep working unchanged. __post_init__ keeps the two in sync.
    protocols: List[str] = field(default_factory=list)
    backend: str = BackendName.FRIDA
    debug: bool = False
    debug_output: bool = False
    custom_hook_script: Optional[str] = None
    environment_file: Optional[str] = None
    install_lsass_hook: bool = True
    proxy: Optional[str] = None  # "host:port" or "[ipv6]:port" format

    def __post_init__(self):
        if self.debug:
            self.debug_output = True
        # Keep the canonical `protocols` list and the primary `protocol` string
        # consistent regardless of which one the caller supplied. When only the
        # legacy `protocol` was set, derive the list from it; otherwise the list
        # is canonical and `protocol` becomes its first (primary) element. This
        # makes the default (`protocols == ["tls"]`, `protocol == "tls"`) and the
        # single-protocol case byte-for-byte identical to before.
        if not self.protocols:
            self.protocols = [self.protocol]
        else:
            self.protocol = self.protocols[0]

    def validate_protocol_backend(self, protocol_handler=None, protocol_name=None) -> None:
        """Validate that the selected backend supports a configured protocol.

        Parameters
        ----------
        protocol_handler
            A ProtocolHandler instance. If None, validation is skipped.
        protocol_name
            The name of the protocol being validated (used in the skip check and
            error message). Defaults to the primary ``self.protocol`` so existing
            single-handler callers are unchanged; multi-protocol callers pass one
            name per selected handler so each selection is validated in turn.

        Raises
        ------
        UnsupportedProtocolBackendError
            When the backend support level is STUB or UNSUPPORTED.
        """
        name = protocol_name or self.protocol
        if name in ("auto", "all"):
            return  # auto/all always start with the Frida default
        if protocol_handler is None:
            return
        from .protocols.base import BackendSupport
        level = protocol_handler.get_backend_support_level(self.backend)
        if level != BackendSupport.FULL:
            supported = [
                name for name, lvl in protocol_handler.supported_backends.items()
                if lvl == BackendSupport.FULL
            ]
            raise UnsupportedProtocolBackendError(
                f"Protocol '{name}' does not fully support the "
                f"'{self.backend}' backend (level: {level}). "
                f"Supported backends: {', '.join(supported)}"
            )

    @classmethod
    def from_legacy_params(
        cls,
        app: str,
        pcap_name: Optional[str] = None,
        spawn_argv: Optional[List[str]] = None,
        verbose: bool = False,
        spawn: bool = False,
        keylog: bool | str = False,
        enable_spawn_gating: bool = False,
        spawn_gating_all: bool = False,
        enable_child_gating: bool = False,
        mobile: bool | str = False,
        live: bool = False,
        environment_file: Optional[str] = None,
        debug_mode: bool = False,
        full_capture: bool = False,
        socket_trace: bool | str = False,
        owner_capture: bool = False,
        owner_strict: bool = False,
        owner_no_dns: bool = False,
        owner_nflog_group: int = 30,
        host: bool | str = False,
        offsets: Optional[str] = None,
        debug_output: bool = False,
        experimental: bool = False,
        anti_root: bool = False,
        payload_modification: bool = False,
        library_scan: bool = False,
        enable_default_fd: bool = False,
        patterns: Optional[str] = None,
        custom_hook_script: Optional[str] = None,
        json_output: Optional[str] = None,
        install_lsass_hook: bool = True,
        timeout: Optional[int] = None,
        script_load_timeout: float = 20.0,
        backend: str = BackendName.FRIDA,
        protocol: str = "tls",
        protocols: Optional[List[str]] = None,
        proxy: Optional[str] = None,
        filter_expression: Optional[str] = None,
        filter_infrastructure: bool = True,
        include_loopback: bool = False,
        auto_relabel: bool = True,
        force_scan_modules: Optional[List[str]] = None,
        quic_capture_mode: str = "stream",
        quic_only: bool = False,
        no_loader_hook: bool = False,
        stealth_loader: bool = False,
        pairip_safe: bool = False,
        probe: bool = False,
        force_anchor_locator: bool = False,
        quic_egress_headers_layer: str = "auto",
        scan_keys_region: Optional[str] = None,
        memory_scan: bool = False,
        memory_scan_patterns: Optional[str] = None,
        memory_scan_interval: float = 2.0,
        memory_scan_emit_unconfirmed: bool = False,
        memory_scan_rc4_known_plaintext: Optional[str] = None,
        memory_scan_rc4_ciphertext: Optional[str] = None,
        scan: Optional[str] = None,
        scan_report: str = "table",
        scan_report_out: Optional[str] = None,
        scan_min_severity: str = "info",
        scan_min_confidence: float = 0.0,
        scan_source: Optional[str] = None,
        scan_category: Optional[str] = None,
        scan_show_pii: bool = False,
        scan_analyzer_path: Optional[List[str]] = None,
    ) -> "FriTapConfig":
        """
        Build a FriTapConfig from the legacy SSL_Logger constructor parameters.
        Ensures full backward compatibility.
        """
        return cls(
            target=app,
            target_argv=spawn_argv,
            device=DeviceConfig(
                mobile=mobile,
                host=host if host else None,
                spawn=spawn,
                enable_spawn_gating=enable_spawn_gating,
                spawn_gating_all=spawn_gating_all,
                enable_child_gating=enable_child_gating,
                timeout=timeout,
                script_load_timeout=script_load_timeout,
            ),
            output=OutputConfig(
                pcap=pcap_name,
                keylog=keylog if isinstance(keylog, str) else (keylog or None),
                json_output=json_output,
                live=live,
                verbose=verbose,
                full_capture=full_capture,
                socket_trace=socket_trace,
                owner_capture=owner_capture,
                owner_strict=owner_strict,
                owner_no_dns=owner_no_dns,
                owner_nflog_group=owner_nflog_group,
                filter_expression=filter_expression,
                filter_infrastructure=filter_infrastructure,
                include_loopback=include_loopback,
                auto_relabel=auto_relabel,
                scan=scan,
                scan_report=scan_report,
                scan_report_out=scan_report_out,
                scan_min_severity=scan_min_severity,
                scan_min_confidence=scan_min_confidence,
                scan_source=scan_source,
                scan_category=scan_category,
                scan_show_pii=scan_show_pii,
                scan_analyzer_path=scan_analyzer_path,
            ),
            hooking=HookingConfig(
                offsets=offsets,
                patterns=patterns,
                experimental=experimental,
                enable_default_fd=enable_default_fd,
                anti_root=anti_root,
                payload_modification=payload_modification,
                library_scan=library_scan,
                force_scan_modules=list(force_scan_modules or []),
                quic_capture_mode=quic_capture_mode,
                quic_only=quic_only,
                no_loader_hook=no_loader_hook,
                stealth_loader=stealth_loader,
                pairip_safe=pairip_safe,
                probe=probe,
                force_anchor_locator=force_anchor_locator,
                quic_egress_headers_layer=quic_egress_headers_layer,
                scan_keys_region=scan_keys_region,
                memory_scan=memory_scan,
                memory_scan_patterns=memory_scan_patterns,
                memory_scan_interval=memory_scan_interval,
                memory_scan_emit_unconfirmed=memory_scan_emit_unconfirmed,
                memory_scan_rc4_known_plaintext=memory_scan_rc4_known_plaintext,
                memory_scan_rc4_ciphertext=memory_scan_rc4_ciphertext,
            ),
            protocol=protocol,
            protocols=list(protocols) if protocols else [protocol],
            backend=backend,
            debug=debug_mode,
            debug_output=debug_output,
            custom_hook_script=custom_hook_script,
            environment_file=environment_file,
            install_lsass_hook=install_lsass_hook,
            proxy=proxy,
        )


# Scan-heavy hooking modes legitimately spend far longer inside the agent's
# top-level code, so the plain bound would fire on a perfectly healthy load.
_SCAN_HEAVY_TIMEOUT_FACTOR = 3


def effective_script_load_timeout(config: "FriTapConfig") -> float | None:
    """Return the ``script.load()`` bound implied by *config*, or ``None``.

    ``None`` means "no bound" and is returned for any non-positive configured
    value, so a user can opt out entirely with ``--script-load-timeout 0``.

    The bound is tripled for pattern matching, library scanning and explicit
    key-region scanning: all three run Memory.scan passes *inside* the agent's
    top-level code, which makes a slow load expected rather than suspicious.
    Scaling instead of disabling keeps a wedged agent detectable.
    """
    configured = config.device.script_load_timeout
    if configured <= 0:
        return None

    hooking = config.hooking
    scan_heavy = bool(
        hooking.patterns
        or hooking.library_scan
        or hooking.scan_keys_region
        or getattr(hooking, "memory_scan", False)
    )
    return configured * _SCAN_HEAVY_TIMEOUT_FACTOR if scan_heavy else configured


def memory_scan_only(config: "FriTapConfig") -> bool:
    """True when ``-ms`` was requested with no other capture/hook surface.

    In that case the main TLS-hooking agent produces nothing — only the heap
    secret-scanner does — so ``instrument()`` skips creating and loading the
    main agent and runs the memory-scan plugin alone. An explicit
    ``hooking.intercept = False`` (the TUI's "memory only" extraction method)
    forces this mode. Otherwise any normal capture surface
    (``-k``/``-p``/``-c``/socket trace/live/JSON/``--scan``/
    ``--scan-keys-region``), offset/pattern hooking (``--offsets``/``--patterns``),
    a library scan (``--library-scan``), a probe, or payload modification pulls
    the main agent back in so both run together. Full capture (``-f``) is not a
    surface of its own: its pcap comes from tcpdump, not the agent, so ``-f -p``
    counts ``-p`` only without ``-f``, and the memory scanner supplies the keys.
    Kept as a pure function of the config so the decision is testable and lives
    next to the other config-derived rules.
    """
    hooking = config.hooking
    # getattr on the gates only: partial mock configs in the test suite may omit
    # the newest fields, and these are the lines they reach before returning.
    if not getattr(hooking, "memory_scan", False):
        return False
    if not getattr(hooking, "intercept", True):
        return True
    out = config.output
    # In full-capture mode the pcap is written by tcpdump on the device, so -p
    # alone does not need the agent's plaintext pcap stream.
    agent_pcap = bool(out.pcap) and not out.full_capture
    other_capture = any((
        out.keylog,
        agent_pcap,
        out.json_output,
        out.socket_trace,
        out.live,
        out.scan,
        config.custom_hook_script,
        hooking.scan_keys_region,
        hooking.probe,
        hooking.payload_modification,
        # Offset/pattern-based hooking and the library scan all run *inside* the
        # main agent, so any of them must pull it back in alongside -ms.
        hooking.offsets,
        hooking.patterns,
        hooking.library_scan,
    ))
    return not other_capture
