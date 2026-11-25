"""Build FriTapConfig objects from the parsed capture CLI arguments."""

from .config import FriTapConfig


def _make_inspection_config(parsed):
    """Build the FriTapConfig the library-inspection commands run against.

    Only flags that influence finding the target and its modules matter;
    ``-ll`` and ``--extract-libraries`` never start a capture session.
    """
    return FriTapConfig.from_legacy_params(
        app=parsed.exec, verbose=parsed.verbose, spawn=parsed.spawn,
        mobile=parsed.mobile, environment_file=parsed.environment,
        debug_mode=parsed.debug, host=parsed.host, offsets=parsed.offsets,
        debug_output=parsed.debug_output, experimental=parsed.experimental,
        anti_root=parsed.anti_root, enable_default_fd=parsed.enable_default_fd,
        patterns=parsed.patterns, custom_hook_script=parsed.custom_script,
        backend=parsed.backend,
    )


def build_capture_config(parsed, install_lsass_hook):
    """The FriTapConfig for a capture session started from the CLI."""
    config = _config_from_capture_flags(parsed, install_lsass_hook)
    # --tap has no from_legacy_params parameter; it lives on OutputConfig only.
    config.output.tap_output = getattr(parsed, "tap", None)
    _apply_profile_flags(config.device, parsed)
    return config


def _apply_profile_flags(device, parsed):
    """--profile / --discover / --also-package (no from_legacy_params parameters)."""
    device.profile_path = getattr(parsed, "profile", None)
    device.discover_seconds = getattr(parsed, "discover", None)
    device.also_packages = list(getattr(parsed, "also_package", None) or [])


def _config_from_capture_flags(parsed, install_lsass_hook):
    """FriTapConfig.from_legacy_params over the parsed capture flags."""
    return FriTapConfig.from_legacy_params(
        app=parsed.exec,
        spawn_argv=getattr(parsed, "exec_argv", None),
        pcap_name=parsed.pcap,
        verbose=parsed.verbose,
        spawn=parsed.spawn,
        keylog=parsed.keylog,
        enable_spawn_gating=parsed.enable_spawn_gating,
        spawn_gating_all=parsed.spawn_gating_all,
        enable_child_gating=parsed.enable_child_gating,
        follow_exec=parsed.follow_exec,
        mobile=parsed.mobile,
        live=parsed.live,
        environment_file=parsed.environment,
        debug_mode=parsed.debug,
        full_capture=parsed.full_capture,
        socket_trace=parsed.socket_tracing,
        owner_capture=getattr(parsed, 'owner_capture', False),
        owner_strict=getattr(parsed, 'owner_strict', False),
        owner_no_dns=getattr(parsed, 'owner_no_dns', False),
        owner_nflog_group=getattr(parsed, 'owner_nflog_group', 30),
        host=parsed.host,
        offsets=parsed.offsets,
        debug_output=parsed.debug_output,
        experimental=parsed.experimental,
        wine_mode=parsed.wine,
        backend_explicit=parsed.backend_explicit,
        anti_root=parsed.anti_root,
        payload_modification=parsed.payload_modification,
        library_scan=parsed.library_scan,
        enable_default_fd=parsed.enable_default_fd,
        patterns=parsed.patterns,
        custom_hook_script=parsed.custom_script,
        json_output=parsed.json,
        json_keys=parsed.json_keys,
        output_format=parsed.pcap_format,
        install_lsass_hook=install_lsass_hook,
        timeout=parsed.timeout,
        script_load_timeout=parsed.script_load_timeout,
        backend=parsed.backend,
        protocol=parsed.protocol,
        protocols=parsed.protocols,
        proxy=parsed.proxy,
        filter_expression=getattr(parsed, 'filter', None),
        filter_infrastructure=getattr(parsed, 'filter_infrastructure', True),
        include_loopback=getattr(parsed, 'include_loopback', False),
        auto_relabel=getattr(parsed, 'auto_relabel', True),
        force_scan_modules=getattr(parsed, 'force_scan_modules', None),
        quic_capture_mode=getattr(parsed, 'quic_capture_mode', 'stream'),
        quic_only=getattr(parsed, 'quic_only', False),
        no_loader_hook=getattr(parsed, 'no_loader_hook', False),
        stealth_loader=getattr(parsed, 'stealth_loader', False),
        pairip_safe=getattr(parsed, 'pairip_safe', False),
        probe=parsed.probe,
        force_anchor_locator=getattr(parsed, 'force_anchor_locator', False),
        attribute_sdk=getattr(parsed, 'attribute_sdk', False),
        quic_egress_headers_layer=getattr(parsed, 'quic_egress_headers_layer', 'auto'),
        scan_keys_region=getattr(parsed, 'scan_keys_region', None),
        memory_scan=bool(getattr(parsed, 'memory_scan', False)),
        memory_scan_patterns=(
            parsed.memory_scan
            if isinstance(getattr(parsed, 'memory_scan', False), str)
            else None
        ),
        memory_scan_interval=getattr(parsed, 'memory_scan_interval', 2.0),
        memory_scan_emit_unconfirmed=bool(
            getattr(parsed, 'ms_emit_unconfirmed', False)
        ),
        memory_scan_rc4_known_plaintext=getattr(
            parsed, 'ms_rc4_known_plaintext', None
        ),
        memory_scan_rc4_ciphertext=getattr(parsed, 'ms_rc4_ciphertext', None),
        scan=getattr(parsed, 'scan', None),
        scan_report=getattr(parsed, 'scan_report', 'table'),
        scan_report_out=getattr(parsed, 'scan_report_out', None),
        scan_min_severity=getattr(parsed, 'scan_min_severity', 'info'),
        scan_min_confidence=getattr(parsed, 'scan_min_confidence', 0.0),
        scan_source=getattr(parsed, 'scan_source', None),
        scan_category=getattr(parsed, 'scan_category', None),
        scan_show_pii=getattr(parsed, 'scan_show_pii', False),
        scan_analyzer_path=getattr(parsed, 'scan_analyzer_path', None),
    )
