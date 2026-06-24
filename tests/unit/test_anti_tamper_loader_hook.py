#!/usr/bin/env python3
"""Unit tests for the --no-loader-hook flag and anti-tamper event surfacing.

Covers the friTap-side of the PairIP SIGSEGV fix (fkie-cad/friTap#64):

  * the --no-loader-hook flag flows into HookingConfig.no_loader_hook,
  * spawn state is carried so the agent can auto-skip the loader hook,
  * the agent's `anti_tamper_detected` message is routed to a structured event
    (so it is no longer silently dropped).
"""

from friTap.config import FriTapConfig
from friTap.constants import ContentType
from friTap.events import EventBus, AntiTamperDetectedEvent
from friTap.fritap_utility import build_anti_tamper_banner
from friTap.message_router import MessageRouter


class TestNoLoaderHookConfig:
    def test_default_is_off(self):
        cfg = FriTapConfig.from_legacy_params(app="com.example")
        assert cfg.hooking.no_loader_hook is False

    def test_flag_sets_hooking_config(self):
        cfg = FriTapConfig.from_legacy_params(app="com.example", no_loader_hook=True)
        assert cfg.hooking.no_loader_hook is True

    def test_spawn_state_is_carried(self):
        assert FriTapConfig.from_legacy_params(app="x", spawn=True).device.spawn is True
        assert FriTapConfig.from_legacy_params(app="x", spawn=False).device.spawn is False

    def test_stealth_loader_flag(self):
        assert FriTapConfig.from_legacy_params(app="x").hooking.stealth_loader is False
        assert FriTapConfig.from_legacy_params(
            app="x", stealth_loader=True).hooking.stealth_loader is True


class TestConfigBatchFields:
    """The agent reads `no_loader_hook` and `spawned` from config_batch; assert
    the values the core would put on the wire for both spawn and attach."""

    def _batch_flags(self, *, spawn: bool, no_loader_hook: bool) -> dict:
        cfg = FriTapConfig.from_legacy_params(
            app="x", spawn=spawn, no_loader_hook=no_loader_hook,
        )
        # Mirror ssl_logger_core.py's config_batch construction for these keys.
        return {
            "no_loader_hook": getattr(cfg.hooking, "no_loader_hook", False),
            "spawned": bool(cfg.device.spawn),
            "stealth_loader": getattr(cfg.hooking, "stealth_loader", False),
        }

    def test_spawn_attach_matrix(self):
        assert self._batch_flags(spawn=True, no_loader_hook=False) == {
            "no_loader_hook": False, "spawned": True, "stealth_loader": False}
        assert self._batch_flags(spawn=False, no_loader_hook=False) == {
            "no_loader_hook": False, "spawned": False, "stealth_loader": False}
        assert self._batch_flags(spawn=True, no_loader_hook=True) == {
            "no_loader_hook": True, "spawned": True, "stealth_loader": False}


class TestAntiTamperRouting:
    def test_detected_payload_emits_event(self):
        bus = EventBus()
        seen = []
        bus.subscribe(AntiTamperDetectedEvent, seen.append)
        router = MessageRouter(bus)

        router.route(
            {"contentType": ContentType.ANTI_TAMPER_DETECTED,
             "library": "libpairipcore.so",
             "name": "Google PairIP (libpairipcore.so)",
             "skippedLoaderHook": True},
            b"",
        )

        assert len(seen) == 1
        assert seen[0].name == "Google PairIP (libpairipcore.so)"
        assert seen[0].library == "libpairipcore.so"
        assert seen[0].skipped_loader_hook is True

    def test_content_type_constant(self):
        assert ContentType.ANTI_TAMPER_DETECTED == "anti_tamper_detected"

    def test_banner_rendered_once_across_multiple_events(self):
        bus = EventBus()
        seen = []
        bus.subscribe(AntiTamperDetectedEvent, seen.append)
        router = MessageRouter(bus)
        payload = {"contentType": ContentType.ANTI_TAMPER_DETECTED,
                   "library": "libpairipcore.so", "name": "Google PairIP",
                   "note": "x", "skippedLoaderHook": True, "reason": "detected"}
        for _ in range(3):
            router.route(dict(payload), b"")
        # All three reach API consumers, but the CLI banner renders only once.
        assert len(seen) == 3
        assert router._anti_tamper_bannered is True


class TestAntiTamperBanner:
    def test_detected_skipped_banner_has_name_and_attach_guidance(self):
        b = build_anti_tamper_banner("Google PairIP (libpairipcore.so)",
                                     "note text", True, "detected")
        assert "ANTI-TAMPER PROTECTION DETECTED: Google PairIP" in b
        assert "ATTACH friTap" in b
        assert "note text" in b
        # blank-line padded so it stands out from surrounding hook logs
        assert b.startswith("\n") and b.endswith("\n")

    def test_flag_only_banner_reads_as_info_notice(self):
        b = build_anti_tamper_banner("", "", True, "flag")
        assert "LOADER HOOK DISABLED (--no-loader-hook)" in b
        assert "ATTACH friTap" in b

    def test_not_skipped_banner_warns_of_possible_crash(self):
        b = build_anti_tamper_banner("Google PairIP", "note", False, "detected")
        assert "may crash" in b
        assert "ATTACH friTap" not in b
