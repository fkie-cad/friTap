"""What :class:`SSL_Logger` tells the agent at startup: the config batch, the
startup handshake, byte patterns, ``--offsets`` and the learned-offsets cache.

The host class owns the state. Names tests patch on ``ssl_logger_core`` are read
through ``_core()`` at call time so the patches take effect.
"""

import json


class AgentConfigMixin:
    """Startup configuration handed to the agent and the blocking handshake answers."""

    def _build_config_batch(self) -> dict:
        """Build the startup configuration for the agent; posts nothing, so it can be rebuilt per script."""
        from ..output.key_material import json_key_material_enabled
        return {
            'offsets': self.offsets_data,
            'patterns': self.pattern_data,
            'socket_tracing': self.socket_trace,
            'defaultFD': self.enable_default_fd,
            'experimental': self.experimental,
            'protocol_select': ",".join(getattr(self._config, 'protocols', None) or [self.protocol]),
            'install_lsass_hook': self.install_lsass_hook,
            'use_modern': getattr(self, 'use_modern', False),
            'library_scan': self.scan_results_data,
            'library_scan_enabled': self._config.hooking.library_scan,
            'ohttp_enabled': getattr(self._config.hooking, 'ohttp_enabled', True),
            'quic_capture_mode': getattr(self._config.hooking, 'quic_capture_mode', 'stream'),
            'quic_only': getattr(self._config.hooking, 'quic_only', False),
            # --no-loader-hook: skip the inline android_dlopen_ext loader
            # trampoline (avoids PairIP/anti-tamper SIGSEGV).
            'no_loader_hook': getattr(self._config.hooking, 'no_loader_hook', False),
            # Spawn state lets the agent auto-skip the loader hook only in
            # spawn mode (where it trips PairIP's startup scan); attach keeps it.
            'spawned': bool(self._config.device.spawn),
            # --lean-wine: defer the full-module Memory.scan sweep so the agent
            # installs fast in a freshly created Wine process, before its first
            # TLS. Set by the Wine process watcher, which attaches each new
            # network-service process the instant it appears.
            'lean_wine': bool(getattr(self, '_wine_lean', False)),
            # Experimental: hardware-breakpoint loader watch (no linker patch).
            'stealth_loader': getattr(self._config.hooking, 'stealth_loader', False),
            # --pairip-safe: minimal symbol-only keylog on BoringSSL libs;
            # skip loader hook, pattern scan, Java and OHTTP.
            'pairip_safe': getattr(self._config.hooking, 'pairip_safe', False),
            # --probe: dry run. The agent reports the platform branch it picked
            # and the hooks it would install, then stops before installing any.
            'probe': bool(getattr(self._config.hooking, 'probe', False)),
            # --boringssl-anchor-only: force the last-resort BoringSSL anchor
            # locator (tier 4) by skipping the pattern tier (debugging aid).
            'force_anchor_locator': bool(getattr(self._config.hooking, 'force_anchor_locator', False)),
            # -f: lets the agent install the --attribute-sdk request-context hooks
            # without plaintext hooks (-f -k); the LSASS helper is kept out.
            'full_capture': self._full_capture_hooks_enabled(),
            # --attribute-sdk: capture the caller backtrace once per connection
            # at the first TLS plaintext hook and emit it as an additive
            # `caller_stack` message (SDK/app attribution). OFF by default; when
            # off the agent's TLS hot path is byte-for-byte unchanged.
            'attribute_sdk': bool(getattr(self._config.hooking, 'attribute_sdk', False)),
            # HTTP/3 egress-headers chain override: "auto" keeps the
            # winner-takes-all fallback; anything else forces one layer so tests
            # can exercise lower tiers.
            'quic_egress_headers_layer': getattr(self._config.hooking, 'quic_egress_headers_layer', 'auto'),
            # Mirrors -do / --debugoutput so the agent skips expensive debug-only
            # enumeration; without it every attach would walk the full
            # Cronet/libmonochrome dynsym (hundreds of MB).
            'debug_output': bool(getattr(self._config, 'debug_output', False)),
            # In -f mode the external tcpdump/scapy thread takes the packets and
            # message_handler discards the in-agent plaintext datalog, so the
            # plaintext hooks are skipped. The wire key 'pcap_enabled' means
            # "install the plaintext hooks", needed by every handler declaring
            # consumes_plaintext (see OutputHandlerFactory.plaintext_hooks_needed).
            'pcap_enabled': self._plaintext_hooks_needed(),
            # Counterpart to pcap_enabled. With only -p (no -k) the agent must skip
            # key extraction, or it floods the channel with KeylogEvents and burns
            # the pattern-scan budget. In -f mode it stays driven by -k, since keys
            # decrypt the full capture. --json-keys also asks for keys; same
            # predicate as the JSON handlers' redaction policy.
            'keylog_enabled': json_key_material_enabled(self._config.output),
            # Protocol-agnostic feature-config passthrough; keys are opt-in
            # feature names (e.g. 'scan_region' for agent/shared/scan/). Empty
            # unless requested, so the default wire shape is unchanged.
            'extensions': (
                {'scan_region': self._config.hooking.scan_keys_region}
                if getattr(self._config.hooking, 'scan_keys_region', None)
                else {}
            ),
            # Cached SSL_read/SSL_write RVAs plus named functions/layout of stripped
            # builds, keyed build_id|size|arch; the user's --offsets win per function.
            'learned_plaintext': self._learned_plaintext_for_agent(),
        }

    def _open_learned_offsets(self) -> None:
        from .learned_offsets_session import LearnedOffsetsSession
        self._learned_offsets = LearnedOffsetsSession.open()
        if self._learned_offsets is not None:
            self._message_router.set_learned_offsets_sink(self._learned_offsets.record)

    def _learned_plaintext_for_agent(self) -> dict:
        session = getattr(self, '_learned_offsets', None)
        return session.agent_entries() if session is not None else {}

    def _save_learned_offsets(self) -> None:
        session = getattr(self, '_learned_offsets', None)
        if session is not None:
            session.save_if_dirty()

    def _answer_startup_handshake(self, payload, script, answered=None) -> bool:
        """Answer one blocking startup-handshake request from the agent.

        Returns True when ``payload`` was answered, so the caller must not enqueue or route it.
        Replies go to ``script`` (the asker), not ``self.script``: ``instrument()`` overwrites
        the latter, and a reply posted to a newer child script leaves the parent blocked in
        ``recv().wait()`` forever. ``config_batch`` and ``anti`` are always answered; the
        ``self.startup`` flag gates only the legacy per-field channels. ``answered`` collects
        the answered request names (observation hook for tests).
        """
        if not isinstance(payload, str):
            return False

        target = script if script is not None else self.script
        if target is None:
            self.logger.warning(
                "Cannot answer startup handshake '%s': no script to reply on", payload
            )
            return False

        if payload == 'config_batch':
            self._backend.post_message(target, 'config_batch', self._build_config_batch())
            if answered is not None:
                answered.add(payload)
            return True

        if payload == 'anti':
            # Terminal request: the agent resumes its top level once this lands,
            # which unblocks script.load().
            self._backend.post_message(target, 'antiroot', self.anti_root)
            self.startup = False
            if answered is not None:
                answered.add(payload)
            return True

        if self.startup:
            from .message_handler import handle_startup_legacy
            if handle_startup_legacy(self, payload, target):
                if answered is not None:
                    answered.add(payload)
                return True

        # Not ours: report it unanswered so the caller keeps routing it. Warn,
        # because the agent only sends bare strings to ask a question and
        # blocks forever on one we cannot answer.
        self.logger.warning(
            "Unanswered agent handshake request '%s' — the agent may be waiting "
            "on a channel this friTap version does not know. Rebuild the agent "
            "bundle with ./dev/compile_agent.sh if it is out of step.", payload
        )
        return False


    def _describe_pattern_source(self):
        """Describe where the agent's byte patterns came from.

        ``pattern_data`` is non-None even without a user file (the defaults are
        always merged), so only ``--patterns`` (``self.patterns``) tells the cases apart.
        """
        if self.patterns:
            return (
                f"Using byte patterns from {self.patterns}, merged over "
                "friTap's bundled default patterns, for hooking"
            )
        return "Using friTap's bundled default byte patterns for hooking"


    @staticmethod
    def _validate_patterns(patterns: dict) -> bool:
        """Validate ``{lib_name: {arch: {function: [pattern_str, ...]}}}``; patterns are space-separated hex bytes, ``?`` wildcards allowed."""
        from ..patterns.loader import PatternLoader
        return PatternLoader.validate(patterns)

    def _load_offsets_data(self):
        """Read ``--offsets`` (a file path, else an inline JSON string).

        The agent silently drops offsets that fail ``JSON.parse``, so invalid file content is warned about here.
        """
        try:
            with open(self.offsets, "r") as offset_file:
                self.offsets_data = offset_file.read()
        except FileNotFoundError:
            try:
                json.loads(self.offsets)
                self.offsets_data = self.offsets
            except ValueError as e:
                self.logger.error(f"Log error, defaulting to auto-detection: {e}")
            return
        self._warn_if_offsets_not_json()

    def _warn_if_offsets_not_json(self):
        try:
            json.loads(self.offsets_data)
        except ValueError as e:
            self.logger.warning(
                f"--offsets file '{self.offsets}' is not valid JSON ({e}); "
                "the agent will ignore these offsets and fall back to "
                "auto-detection. See offsets_example.json for the format.")

    def load_patterns(self):
        """Load the default patterns and deep-merge the user's on top (only the entries they name are overridden)."""
        from ..patterns.loader import PatternLoader
        self.pattern_data = PatternLoader.load(self.patterns, self.logger)

    def _apply_sibling_coverage_suppression(self, scan_results: list[dict]) -> None:
        """Suppress pattern scans of Cronet runtime modules whose BoringSSL lives in a sibling module.

        Some Cronet builds put BoringSSL in e.g. ``stable_cronet_libssl.so`` while
        ``libmainlinecronet.<ver>.so`` only imports it, so scanning the runtime is futile.
        Marks such scan results ``covered_by_sibling`` (read by the agent's library_scanner)
        and strips them from ``self.pattern_data``. ``--force-scan <name>`` or
        ``FRITAP_FORCE_SCAN`` (comma-separated) opts back in.
        """
        from ..protocols.tls_handler import covered_by_sibling, strip_covered_modules

        force_set = self._config.hooking.force_scan_modules or ()
        covered = covered_by_sibling(scan_results, force_scan_modules=force_set)
        if not covered:
            return

        for entry in scan_results:
            name = entry.get("name")
            if name in covered:
                entry["covered_by_sibling"] = covered[name]

        self.logger.info(
            "Cronet split topology detected; skipping %d redundant scan(s): %s",
            len(covered), ", ".join(covered.keys()),
        )
        self.pattern_data = strip_covered_modules(
            self.pattern_data, covered, force_scan_modules=force_set
        )

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep-merge two dicts; ``override`` leaf values win."""
        from ..patterns.loader import PatternLoader
        return PatternLoader.deep_merge(base, override)
