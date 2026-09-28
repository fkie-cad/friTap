"""merge_memory_scan_sidecars: the shared manifest sidecar-merge helper."""

from friTap.offline.keylog_picker import merge_memory_scan_sidecars


def _write(path, *lines):
    path.write_text("".join(f"{ln}\n" for ln in lines), encoding="utf-8")
    return str(path)


def test_merges_tls_mtproto_alias_and_generic_protocols(tmp_path):
    hook_tls = _write(tmp_path / "hook.tls.log", "CLIENT_RANDOM aa bb")
    ms_tls = _write(tmp_path / "ms.log", "CLIENT_RANDOM cc dd")
    ms_mt = _write(tmp_path / "ms.mtproto.keylog", "MTPROTO_OBF_KEY 1")
    ms_rc4 = _write(tmp_path / "ms.rc4.keylog", "RC4_KEY x")
    current = {"tls": hook_tls}

    out = merge_memory_scan_sidecars(
        {"tls": ms_tls, "telegram": ms_mt, "rc4": ms_rc4},
        current.get, out_dir=str(tmp_path))

    assert set(out) == {"tls", "mtproto", "rc4"}
    with open(out["tls"], encoding="utf-8") as fh:
        assert fh.read().splitlines() == ["CLIENT_RANDOM aa bb", "CLIENT_RANDOM cc dd"]


def test_missing_sidecar_is_skipped(tmp_path):
    out = merge_memory_scan_sidecars(
        {"tls": str(tmp_path / "absent.log"), "mtproto": ""},
        lambda _proto: None, out_dir=str(tmp_path))
    assert out == {}
