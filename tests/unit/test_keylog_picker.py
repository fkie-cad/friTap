"""Tests for the pure pcap-to-tap keylog picker helpers.

Covers the picker entry order (tls first, custom last, rc4 and schannel hidden),
the display names, custom-cipher grouping, Schannel sidecar detection by name
and by content, the generic picker_group/accepts_keylog routing in
``resolve_keylog_protocol`` and the readable ``keylog_protocol_label``.
"""

from __future__ import annotations

import pytest

import friTap.offline.pcap_to_tap  # noqa: F401  (registers the built-ins)
from friTap.offline import keylog_picker as kp
from friTap.offline.registry import OfflineDecryptorEntry, OfflineDecryptorRegistry
from friTap.offline.schannel.unpaired import looks_like_unpaired
from tests.unit._offline_helpers import make_offline_entry

_TLS12_MASTER = "ab" * 48


def _entry(name: str, picker_group: str = "", **overrides) -> OfflineDecryptorEntry:
    return make_offline_entry(name, picker_group=picker_group, **overrides)


def _registry(*entries: OfflineDecryptorEntry) -> OfflineDecryptorRegistry:
    registry = OfflineDecryptorRegistry()
    for entry in entries:
        registry.register(entry)
    return registry


# --- picker names ----------------------------------------------------------

def test_default_picker_order_groups_custom_and_hides_schannel():
    names = kp.picker_protocol_names()
    assert names[:3] == ["tls", "mtproto", "telegram"]
    assert names[-1] == "custom"
    assert "rc4" not in names
    assert "schannel" not in names


def test_default_offline_custom_ciphers_is_rc4():
    assert kp.offline_custom_ciphers() == ["rc4"]


def test_picker_omits_custom_when_registry_has_no_custom_cipher():
    registry = _registry(_entry("mtproto"), _entry("schannel", picker_group="tls"))
    assert kp.offline_custom_ciphers(registry) == []
    assert kp.picker_protocol_names(registry) == ["tls", "mtproto"]


def test_picker_groups_registered_custom_cipher_last():
    registry = _registry(_entry("rc4"), _entry("signal"))
    assert kp.picker_protocol_names(registry) == ["tls", "signal", "custom"]


def test_offline_custom_ciphers_never_raises(monkeypatch):
    import friTap.protocols.registry as proto_registry

    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(proto_registry, "custom_cipher_names", _boom)
    assert kp.offline_custom_ciphers(_registry(_entry("rc4"))) == []


def test_picker_falls_back_to_tls_on_error():
    class _Broken(OfflineDecryptorRegistry):
        def list(self):
            raise RuntimeError("broken")

    assert kp.picker_protocol_names(_Broken()) == ["tls"]


def test_picker_display_name():
    assert kp.picker_display_name("custom") == "custom encryption"
    assert kp.picker_display_name("mtproto") == "mtproto"


def test_schannel_entry_declares_tls_picker_group():
    from friTap.offline.registry import get_offline_decryptor_registry

    assert get_offline_decryptor_registry().get("schannel").picker_group == "tls"
    assert get_offline_decryptor_registry().get("mtproto").picker_group == ""


# --- sidecar detection -----------------------------------------------------

def test_sidecar_detected_by_name_even_if_missing(tmp_path):
    assert looks_like_unpaired(str(tmp_path / "scan.schannel.unpaired"))


@pytest.mark.parametrize("kind", ["schannel_tls12_master", "schannel_tls13_secret"])
def test_sidecar_detected_by_content(tmp_path, kind):
    path = tmp_path / "secrets.log"
    path.write_text(f"# header\n\n{kind} {_TLS12_MASTER} - 771\n")
    assert looks_like_unpaired(str(path))


def test_nss_keylog_is_not_a_sidecar(tmp_path):
    path = tmp_path / "sslkeys.log"
    path.write_text(f"CLIENT_RANDOM {'00' * 32} {_TLS12_MASTER}\n")
    assert not looks_like_unpaired(str(path))


def test_missing_file_is_not_a_sidecar(tmp_path):
    assert not looks_like_unpaired(str(tmp_path / "nope.log"))
    assert not looks_like_unpaired("")


# --- routing ---------------------------------------------------------------

def test_resolve_routes_tls_sidecar_to_schannel(tmp_path):
    sidecar = str(tmp_path / "x.schannel.unpaired")
    assert kp.resolve_keylog_protocol("tls", sidecar) == "schannel"


def test_resolve_keeps_tls_for_nss_keylog(tmp_path):
    path = tmp_path / "keys.log"
    path.write_text(f"CLIENT_RANDOM {'00' * 32} {_TLS12_MASTER}\n")
    assert kp.resolve_keylog_protocol("tls", str(path)) == "tls"


def test_resolve_keeps_tls_when_schannel_not_registered(tmp_path):
    sidecar = str(tmp_path / "x.schannel.unpaired")
    assert kp.resolve_keylog_protocol("tls", sidecar, registry=_registry()) == "tls"


def test_resolve_passes_through_other_picker_names(tmp_path):
    sidecar = str(tmp_path / "x.schannel.unpaired")
    assert kp.resolve_keylog_protocol("mtproto", sidecar) == "mtproto"
    assert kp.resolve_keylog_protocol("custom", sidecar) == "custom"


def test_resolve_routes_generically_via_picker_group(tmp_path):
    path = str(tmp_path / "keys.foo")
    registry = _registry(
        _entry("rejecter", picker_group="mygroup", accepts_keylog=lambda _p: False),
        _entry("other_group", picker_group="tls", accepts_keylog=lambda _p: True),
        _entry("foo", picker_group="mygroup", accepts_keylog=lambda p: p.endswith(".foo")),
    )
    assert kp.resolve_keylog_protocol("mygroup", path, registry=registry) == "foo"
    assert kp.resolve_keylog_protocol("mygroup", str(tmp_path / "k.bar"), registry=registry) == "mygroup"


def test_resolve_ignores_grouped_entry_without_predicate(tmp_path):
    registry = _registry(_entry("foo", picker_group="mygroup"))
    assert kp.resolve_keylog_protocol("mygroup", str(tmp_path / "k"), registry=registry) == "mygroup"


def test_resolve_survives_raising_predicate(tmp_path):
    def _boom(_path):
        raise RuntimeError("boom")

    registry = _registry(_entry("foo", picker_group="mygroup", accepts_keylog=_boom))
    assert kp.resolve_keylog_protocol("mygroup", str(tmp_path / "k"), registry=registry) == "mygroup"


def test_looks_like_unpaired_misses_plain_text(tmp_path):
    path = tmp_path / "notes.log"
    path.write_text("# only a comment\n\nhello world\n")
    assert not looks_like_unpaired(str(path))


def test_keylog_protocol_label_readable_names():
    assert kp.keylog_protocol_label("rc4") == "custom encryption (rc4)"
    assert kp.keylog_protocol_label("schannel") == "tls (schannel)"
    assert kp.keylog_protocol_label("tls") == "tls"
    assert kp.keylog_protocol_label("signal") == "signal"


def test_keylog_protocol_label_generic_group_custom_and_plain():
    registry = _registry(_entry("foo", picker_group="mygroup"), _entry("rc4"), _entry("bar"))
    assert kp.keylog_protocol_label("foo", registry=registry) == "mygroup (foo)"
    assert kp.keylog_protocol_label("rc4", registry=registry) == "custom encryption (rc4)"
    assert kp.keylog_protocol_label("bar", registry=registry) == "bar"


def test_keylog_protocol_label_uses_precomputed_custom_ciphers():
    registry = _registry(_entry("bar"))
    label = kp.keylog_protocol_label("bar", custom_ciphers=["bar"], registry=registry)
    assert label == "custom encryption (bar)"


def test_schannel_entry_accepts_sidecar_predicate():
    from friTap.offline.registry import get_offline_decryptor_registry

    assert get_offline_decryptor_registry().get("schannel").accepts_keylog is looks_like_unpaired


def test_custom_picker_name_matches_protocol_custom_group():
    from friTap.protocols.registry import CUSTOM_GROUP

    assert kp.CUSTOM_PICKER_NAME == CUSTOM_GROUP == "custom"


# --- merge_keylogs (union + dedupe for same-protocol keylogs) --------------

class TestMergeKeylogs:
    """The ``merge_keylogs`` helper backing the wizard's same-protocol merge."""

    def _read(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()

    def test_union_and_dedupe_of_mtproto_key_lines(self, tmp_path):
        """The exact user case: an E2E-only ``telegram.keys.log`` merged with an
        auth+E2E+OBF memory-scan keylog yields ONE file carrying all three key
        types, with the shared E2E line de-duplicated."""
        from friTap.protocols.mtproto_keylog_spec import (
            format_e2e_line,
            format_line,
            format_obf_line,
        )
        e2e = format_e2e_line(
            key_fingerprint="11" * 8, shared_key="22" * 256, chat_id=-1
        )
        auth = format_line(dc_id=2, auth_key_id="ab" * 8, auth_key="cd" * 256, key_type="perm")
        obf = format_obf_line(
            key_out="aa" * 32, iv_out="bb" * 16,
            key_in="cc" * 32, iv_in="dd" * 16,
        )

        e2e_only = tmp_path / "telegram.keys.log"
        e2e_only.write_text(f"# telegram e2e keylog\n{e2e}\n")
        memscan = tmp_path / "Telegram_memscan.mtproto.keylog"
        # The memscan file repeats the same E2E line (must de-dupe) and adds
        # the auth + obf lines.
        memscan.write_text(
            f"# memscan keylog\n{auth}\n{e2e}\n{obf}\n"
        )

        merged = kp.merge_keylogs(
            [str(e2e_only), str(memscan)], "mtproto", out_dir=str(tmp_path)
        )
        assert merged is not None
        assert merged.path.endswith(".merged.mtproto.keylog")
        content = self._read(merged.path)

        # All three MTProto key types survive.
        assert "MTPROTO_AUTH_KEY" in content
        assert "MTPROTO_E2E_KEY" in content
        assert "MTPROTO_OBF_KEY" in content
        # The shared E2E line appears exactly once (de-duplicated union).
        assert content.count(e2e) == 1
        # Three distinct key lines total.
        assert merged.key_count == 3
        # A single header/comment block is preserved (union of both comments).
        assert "# telegram e2e keylog" in content
        assert "# memscan keylog" in content

    def test_identical_files_collapse_to_one_copy(self, tmp_path):
        from friTap.protocols.mtproto_keylog_spec import format_e2e_line
        e2e = format_e2e_line(
            key_fingerprint="33" * 8, shared_key="44" * 256, chat_id=7
        )
        a = tmp_path / "a.log"
        b = tmp_path / "b.log"
        a.write_text(f"{e2e}\n")
        b.write_text(f"{e2e}\n")
        merged = kp.merge_keylogs([str(a), str(b)], "mtproto", out_dir=str(tmp_path))
        assert merged is not None
        assert merged.key_count == 1
        assert self._read(merged.path).count(e2e) == 1

    def test_remerge_keeps_stable_name(self, tmp_path):
        """Re-merging an already-merged file keeps the ``.merged.<proto>`` name
        stable instead of growing ``.merged.merged.…`` on each pass."""
        first = tmp_path / "keys.log"
        first.write_text("MTPROTO_OBF_KEY line-one\n")
        second = tmp_path / "more.log"
        second.write_text("MTPROTO_OBF_KEY line-two\n")
        merged = kp.merge_keylogs([str(first), str(second)], "mtproto", out_dir=str(tmp_path))
        assert merged is not None
        third = tmp_path / "third.log"
        third.write_text("MTPROTO_OBF_KEY line-three\n")
        remerged = kp.merge_keylogs(
            [merged.path, str(third)], "mtproto", out_dir=str(tmp_path)
        )
        assert remerged is not None
        import os
        assert os.path.basename(remerged.path) == "keys.merged.mtproto.keylog"
        assert remerged.key_count == 3

    def test_unreadable_inputs_return_none(self, tmp_path):
        missing_a = str(tmp_path / "nope-a.log")
        missing_b = str(tmp_path / "nope-b.log")
        assert kp.merge_keylogs([missing_a, missing_b], "tls", out_dir=str(tmp_path)) is None

    def test_never_raises_on_bad_input(self):
        # Total contract: bogus args degrade to None rather than raising.
        assert kp.merge_keylogs([None], "mtproto") is None  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# count_distinct_keys (Fix A1) — the union count behind the Capture Results dialog
# ---------------------------------------------------------------------------

def test_count_distinct_keys_unions_and_dedupes(tmp_path):
    a = tmp_path / "hook.log"
    a.write_text("# header\nKEY_A\nKEY_B\n")
    b = tmp_path / "memscan.log"
    b.write_text("# header\nKEY_B\nKEY_C\nKEY_D\n")  # KEY_B overlaps
    assert kp.count_distinct_keys([str(a)]) == 2
    assert kp.count_distinct_keys([str(b)]) == 3
    assert kp.count_distinct_keys([str(a), str(b)]) == 4  # union, deduped


def test_count_distinct_keys_skips_missing_and_empty(tmp_path):
    a = tmp_path / "hook.log"
    a.write_text("KEY_A\n")
    assert kp.count_distinct_keys([str(a), str(tmp_path / "nope.log"), "", None]) == 1
    assert kp.count_distinct_keys([]) == 0
