"""Tests for friTap.learned_offsets (persisted BoringSSL plaintext RVAs)."""

import json
import os
import threading
from pathlib import Path

import pytest

from friTap import learned_offsets as lo
from friTap.learned_offsets import LearnedOffsetsStore, make_key

BUILD_ID = "ab" * 20
SHA_READ = "1" * 64
SHA_WRITE = "2" * 64
LOGGER = "friTap.learned_offsets"
# Shared with the agent's key test so both sides build the same cache key.
KEY_CASES = Path(__file__).resolve().parents[1] / "fixtures" / "learned_offsets_key_cases.json"


def message(**overrides):
    base = {
        "module": "libcronet.so",
        "build_id": BUILD_ID,
        "size": 0x100000,
        "arch": "arm64",
        "rvas": {"SSL_read": 0x1000, "SSL_write": 0x2000},
        "prologue_sha256": {"SSL_read": SHA_READ, "SSL_write": SHA_WRITE},
    }
    base.update(overrides)
    return base


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        self.now += 1
        return self.now


@pytest.fixture
def cache_path(tmp_path):
    return str(tmp_path / "cache" / "learned_offsets.json")


@pytest.fixture
def store(cache_path):
    return LearnedOffsetsStore(cache_path, clock=FakeClock())


def warnings_in(records):
    return [r for r in records if r.levelname == "WARNING"]


# ---- keys --------------------------------------------------------------

def test_key_format():
    assert make_key(BUILD_ID, 4096, "arm64") == f"{BUILD_ID}|4096|arm64"


@pytest.mark.parametrize("case", json.loads(KEY_CASES.read_text()),
                         ids=lambda case: case["arch"])
def test_key_matches_cross_language_fixture(case):
    assert make_key(case["build_id"], case["size"], case["arch"]) == case["key"]


@pytest.mark.parametrize("arch", ["ia32", "x64", "arm", "arm64", "mips"])
def test_every_frida_arch_is_accepted(store, arch):
    assert store.record(message(arch=arch)) == make_key(BUILD_ID, 0x100000, arch)


def test_record_returns_key(store):
    assert store.record(message()) == f"{BUILD_ID}|{0x100000}|arm64"


def test_isa_separation(store):
    store.record(message(arch="arm64"))
    store.record(message(arch="x64", rvas={"SSL_read": 0x3000, "SSL_write": 0x4000}))
    entries = store.entries_for_agent()
    assert len(entries) == 2
    assert entries[make_key(BUILD_ID, 0x100000, "x64")]["rvas"]["SSL_read"] == 0x3000
    assert entries[make_key(BUILD_ID, 0x100000, "arm64")]["rvas"]["SSL_read"] == 0x1000


def test_uppercase_hex_normalised(store):
    key = store.record(message(build_id=BUILD_ID.upper(),
                               prologue_sha256={"SSL_read": "A" * 64, "SSL_write": SHA_WRITE}))
    assert key.startswith(BUILD_ID + "|")
    assert store.entries_for_agent()[key]["prologue_sha256"]["SSL_read"] == "a" * 64


# ---- validation --------------------------------------------------------

@pytest.mark.parametrize("overrides", [
    {"build_id": None},
    {"build_id": ""},
    {"build_id": "xyz"},
    {"build_id": "abc"},  # odd length
    {"size": 0},
    {"size": True},
    {"size": "4096"},
    {"arch": ""},
    {"arch": "ARM64 "},
    {"arch": "x86_64"},
    {"module": "../evil.so"},
    {"module": "dir/lib.so"},
    {"module": ""},
    {"module": 5},
    {"rvas": {"SSL_read": 0x1000}},
    {"rvas": {"SSL_read": 0x1000, "SSL_write": 0x200000}},  # beyond size
    {"rvas": {"SSL_read": 0, "SSL_write": 0x2000}},
    {"rvas": {"SSL_read": -1, "SSL_write": 0x2000}},
    {"rvas": {"SSL_read": True, "SSL_write": 0x2000}},
    {"rvas": {"SSL_read": "0x1000", "SSL_write": 0x2000}},
    {"rvas": None},
    {"prologue_sha256": {"SSL_read": "zz" * 32, "SSL_write": SHA_WRITE}},
    {"prologue_sha256": {"SSL_read": "1" * 63, "SSL_write": SHA_WRITE}},
    {"prologue_sha256": {"SSL_read": SHA_READ}},
    {"prologue_sha256": "nope"},
])
def test_record_rejects_invalid(store, overrides):
    assert store.record(message(**overrides)) is None
    assert len(store) == 0


@pytest.mark.parametrize("module", ["Electron Framework", "Google Chrome Framework"])
def test_macho_uuid_and_framework_name_are_accepted(store, module):
    uuid = "4c4c44ad55553144a1b2c3d4e5f60718"  # 16-byte LC_UUID as the agent hexes it
    key = store.record(message(module=module, build_id=uuid.upper()))
    assert key == make_key(uuid, 0x100000, "arm64")


@pytest.mark.parametrize("build_id", [
    "8b7e14e7adb2764b4c4c44205044422e00000001",  # PE RSDS GUID (canonical order) + age %08x
    "6afaff77002ee000",                          # PE fallback: TimeDateStamp + SizeOfImage
])
def test_pe_identity_and_dll_name_are_accepted(store, build_id):
    key = store.record(message(module="nss3.dll", build_id=build_id, arch="x64"))
    assert key == make_key(build_id, 0x100000, "x64")


@pytest.mark.parametrize("module", [" lead.so", "trail.so ", "a" * 256, "two\nlines"])
def test_module_name_space_rules(store, module):
    assert store.record(message(module=module)) is None


def test_record_rejects_missing_build_id(store):
    msg = message()
    del msg["build_id"]
    assert store.record(msg) is None


def test_record_rejects_non_dict(store):
    assert store.record(["not", "a", "dict"]) is None


# ---- load robustness ---------------------------------------------------

def test_load_missing_file_is_empty_and_silent(store, fritap_log_records):
    records = fritap_log_records(LOGGER)
    assert store.load() == 0
    assert warnings_in(records) == []


@pytest.mark.parametrize("content", ["{not json", "[]", '{"entries": []}', "\x00\xff"])
def test_load_corrupt_file_warns_once(store, cache_path, content, fritap_log_records):
    os.makedirs(os.path.dirname(cache_path))
    with open(cache_path, "w", encoding="latin-1") as fh:
        fh.write(content)
    records = fritap_log_records(LOGGER)
    assert store.load() == 0
    assert len(warnings_in(records)) == 1


def test_load_oversized_file(store, cache_path, fritap_log_records):
    os.makedirs(os.path.dirname(cache_path))
    with open(cache_path, "w") as fh:
        fh.write(" " * (lo.MAX_FILE_BYTES + 1))
    records = fritap_log_records(LOGGER)
    assert store.load() == 0
    assert len(warnings_in(records)) == 1


def test_load_unreadable_path_does_not_raise(tmp_path, fritap_log_records):
    records = fritap_log_records(LOGGER)
    store = LearnedOffsetsStore(str(tmp_path))  # a directory, not a file
    assert store.load() == 0
    assert len(warnings_in(records)) == 1


def test_load_drops_invalid_entries_and_rekeys(store, cache_path):
    good = dict(message(), last_seen=5)
    payload = {"version": 1, "entries": {"forged|1|x64": good, "bad": {"module": "x"}}}
    os.makedirs(os.path.dirname(cache_path))
    with open(cache_path, "w") as fh:
        json.dump(payload, fh)
    assert store.load() == 1
    assert list(store.entries_for_agent()) == [make_key(BUILD_ID, 0x100000, "arm64")]


# ---- save / round trip -------------------------------------------------

def test_round_trip(store, cache_path):
    key = store.record(message())
    assert store.save() is True
    fresh = LearnedOffsetsStore(cache_path)
    assert fresh.load() == 1
    assert fresh.entries_for_agent() == {key: {
        "module": "libcronet.so",
        "rvas": {"SSL_read": 0x1000, "SSL_write": 0x2000},
        "prologue_sha256": {"SSL_read": SHA_READ, "SSL_write": SHA_WRITE},
        "functions": {},
        "layout": {},
    }}


def test_save_failure_mid_write_keeps_original(store, cache_path, monkeypatch):
    store.record(message())
    assert store.save()
    with open(cache_path, "rb") as fh:
        original = fh.read()

    store.record(message(arch="x64"))

    def failing_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(lo.os, "replace", failing_replace)
    assert store.save() is False
    with open(cache_path, "rb") as fh:
        assert fh.read() == original
    leftovers = [n for n in os.listdir(os.path.dirname(cache_path)) if n.endswith(".tmp")]
    assert leftovers == []


def test_save_failure_during_write_keeps_original(store, cache_path, monkeypatch):
    store.record(message())
    assert store.save()
    with open(cache_path, "rb") as fh:
        original = fh.read()

    def failing_fsync(fd):
        raise OSError("io error")

    monkeypatch.setattr(lo.os, "fsync", failing_fsync)
    assert store.save() is False
    with open(cache_path, "rb") as fh:
        assert fh.read() == original


def test_default_path_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv(lo.CACHE_DIR_ENV, str(tmp_path))
    assert lo.default_cache_path() == str(tmp_path / lo.CACHE_FILE_NAME)


def test_default_path_without_env(monkeypatch):
    monkeypatch.delenv(lo.CACHE_DIR_ENV, raising=False)
    assert lo.default_cache_path().endswith(lo.CACHE_FILE_NAME)


# ---- cap / eviction ----------------------------------------------------

def test_cap_evicts_least_recently_seen(cache_path):
    store = LearnedOffsetsStore(cache_path, max_entries=3, clock=FakeClock())
    keys = [store.record(message(size=0x100000 + i)) for i in range(3)]
    store.record(message(size=0x100000))  # refresh the oldest
    newest = store.record(message(size=0x200000))
    remaining = set(store.entries_for_agent())
    assert remaining == {keys[0], keys[2], newest}


def test_load_applies_cap(store, cache_path):
    store.record(message(size=0x100000))
    store.record(message(size=0x100001))
    store.save()
    small = LearnedOffsetsStore(cache_path, max_entries=1)
    assert small.load() == 1
    assert list(small.entries_for_agent()) == [make_key(BUILD_ID, 0x100001, "arm64")]


def test_concurrent_record_and_save(cache_path):
    store = LearnedOffsetsStore(cache_path, max_entries=50)

    def worker(offset):
        for i in range(20):
            store.record(message(size=0x100000 + offset * 100 + i))
            store.save()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(store) == 50
    fresh = LearnedOffsetsStore(cache_path, max_entries=50)
    assert fresh.load() == 50


# ---- agent views -------------------------------------------------------

def test_entries_for_agent_is_a_copy(store):
    key = store.record(message())
    store.entries_for_agent()[key]["rvas"]["SSL_read"] = 1
    assert store.entries_for_agent()[key]["rvas"]["SSL_read"] == 0x1000


# ---- multi-process merge -----------------------------------------------

def test_save_merges_entries_another_process_wrote(cache_path):
    ours = LearnedOffsetsStore(cache_path, clock=FakeClock())
    theirs = LearnedOffsetsStore(cache_path, clock=FakeClock())
    ours.load()
    theirs.load()
    their_key = theirs.record(message(arch="x64"))
    assert theirs.save()
    our_key = ours.record(message())
    assert ours.save()
    fresh = LearnedOffsetsStore(cache_path)
    fresh.load()
    assert set(fresh.entries_for_agent()) == {our_key, their_key}


def test_merge_newest_last_seen_wins_per_key(cache_path):
    old_clock, new_clock = FakeClock(), FakeClock()
    new_clock.now = 5000.0
    stale = LearnedOffsetsStore(cache_path, clock=old_clock)
    newer = LearnedOffsetsStore(cache_path, clock=new_clock)
    newer.record(message(rvas={"SSL_read": 0x3000, "SSL_write": 0x4000}))
    assert newer.save()
    key = stale.record(message())  # older last_seen than the file's entry
    assert stale.save()
    fresh = LearnedOffsetsStore(cache_path)
    fresh.load()
    assert fresh.entries_for_agent()[key]["rvas"] == {"SSL_read": 0x3000, "SSL_write": 0x4000}


def test_merge_respects_the_cap(cache_path):
    other = LearnedOffsetsStore(cache_path, clock=FakeClock())
    for i in range(3):
        other.record(message(size=0x100000 + i))
    assert other.save()
    clock = FakeClock()
    clock.now = 9000.0
    small = LearnedOffsetsStore(cache_path, max_entries=2, clock=clock)
    newest = small.record(message(size=0x200000))
    assert small.save()
    assert len(small) == 2
    assert newest in small.entries_for_agent()
    with open(cache_path) as fh:
        assert len(json.load(fh)["entries"]) == 2


def test_save_over_unreadable_file_warns_once_then_debug(cache_path, fritap_log_records):
    os.makedirs(os.path.dirname(cache_path))
    with open(cache_path, "w") as fh:
        fh.write("{not json")
    store = LearnedOffsetsStore(cache_path, clock=FakeClock())
    records = fritap_log_records(LOGGER)
    store.load()
    store.record(message())
    assert store.save()  # rewrites the corrupt file with our entries
    with open(cache_path, "w") as fh:
        fh.write("{still not json")
    store.save()
    assert len(warnings_in(records)) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_saved_cache_is_world_readable(store, cache_path):
    store.record(message())
    assert store.save()
    assert os.stat(cache_path).st_mode & 0o777 == 0o644


# ---- cache hits --------------------------------------------------------

def test_touch_refreshes_last_seen_so_hot_entries_survive_eviction(cache_path):
    store = LearnedOffsetsStore(cache_path, max_entries=2, clock=FakeClock())
    hot = store.record(message(size=0x100000))
    cold = store.record(message(size=0x100001))
    assert store.touch(message(size=0x100000, cache_hit=True)) == hot
    newest = store.record(message(size=0x100002))
    assert set(store.entries_for_agent()) == {hot, newest}
    assert cold not in store.entries_for_agent()


def test_touch_needs_only_key_fields_for_a_known_entry(store):
    key = store.record(message())
    hit = {"module": "libcronet.so", "build_id": BUILD_ID, "size": 0x100000,
           "arch": "arm64", "cache_hit": True}
    assert store.touch(hit) == key
    assert store.entries_for_agent()[key]["rvas"] == {"SSL_read": 0x1000, "SSL_write": 0x2000}


@pytest.mark.parametrize("overrides", [{"arch": "sparc"}, {"build_id": "zz"},
                                       {"size": 0}, {"module": "a/b"}])
def test_touch_rejects_bad_key_fields(store, overrides):
    store.record(message())
    assert store.touch(message(cache_hit=True, **overrides)) is None


def test_touch_unknown_key_records_a_full_entry(store):
    assert store.touch(message(cache_hit=True)) == make_key(BUILD_ID, 0x100000, "arm64")


def test_touch_unknown_key_without_rvas_is_rejected(store):
    hit = {"module": "libcronet.so", "build_id": BUILD_ID, "size": 0x100000, "arch": "arm64"}
    assert store.touch(hit) is None
    assert len(store) == 0


# ---- named functions / layout --------------------------------------------

SHA_FN = "3" * 64
KEY = make_key(BUILD_ID, 0x100000, "arm64")


def module_message(functions=None, layout=None, **overrides):
    base = {"module": "libcronet.so", "build_id": BUILD_ID, "size": 0x100000, "arch": "arm64"}
    if functions is not None:
        base["functions"] = functions
    if layout is not None:
        base["layout"] = layout
    base.update(overrides)
    return base


def fn(rva, digest=SHA_FN):
    return {"rva": rva, "prologue_sha256": digest}


def test_functions_only_entry_is_valid(store):
    key = store.record(module_message(functions={"boringssl.ssl_log_secret": fn(0x3000)}))
    assert key == KEY
    assert store.entries_for_agent()[key] == {
        "module": "libcronet.so",
        "functions": {"boringssl.ssl_log_secret": fn(0x3000)},
        "layout": {},
    }


def test_layout_only_entry_is_valid(store):
    key = store.record(module_message(layout={"boringssl.ssl_ctx_keylog_callback": 0x148}))
    assert store.entries_for_agent()[key]["layout"] == {"boringssl.ssl_ctx_keylog_callback": 0x148}


def test_entry_without_any_valid_item_and_no_rvas_is_rejected(store):
    assert store.record(module_message(functions={"Bad": fn(0x3000)}, layout={})) is None
    assert len(store) == 0


@pytest.mark.parametrize("name", [
    "boringssl.ssl_log_secret",
    "quiche.on_data_frame_payload",
    "quiche.frame.OnStreamFrame",
    "a.b.c.d",
])
def test_function_names_accepted(store, name):
    store.record(module_message(functions={name: fn(0x3000)}))
    assert name in store.entries_for_agent()[KEY]["functions"]


@pytest.mark.parametrize("name, item", [
    ("noNamespace", fn(0x3000)),
    ("Upper.ns", fn(0x3000)),
    ("a.b.c.d.e", fn(0x3000)),
    ("a..b", fn(0x3000)),
    ("a.b-c", fn(0x3000)),
    ("a." + "x" * 130, fn(0x3000)),
    ("ok.zero_rva", fn(0)),
    ("ok.beyond_size", fn(0x100000)),
    ("ok.bool_rva", fn(True)),
    ("ok.str_rva", fn("0x3000")),
    ("ok.bad_hash", fn(0x3000, "zz" * 32)),
    ("ok.short_hash", fn(0x3000, "3" * 63)),
    ("ok.no_hash", {"rva": 0x3000}),
    ("ok.not_object", 0x3000),
])
def test_bad_function_item_is_dropped_rest_kept(store, name, item, fritap_log_records):
    records = fritap_log_records(LOGGER)
    store.record(module_message(functions={name: item, "good.fn": fn(0x4000)}))
    assert store.entries_for_agent()[KEY]["functions"] == {"good.fn": fn(0x4000)}
    assert any(r.levelname == "DEBUG" and "dropping" in r.getMessage() for r in records)


@pytest.mark.parametrize("name, value", [
    ("ok.too_small", lo.LAYOUT_MIN - 1),
    ("ok.too_big", lo.LAYOUT_MAX + 1),
    ("ok.bool", True),
    ("ok.float", 1.5),
    ("ok.vtableRva", 0),
    ("ok.vtableRva", -1),
    ("ok.vtableRva", lo.LAYOUT_RVA_MAX),
    ("Bad.name", 1),
])
def test_bad_layout_item_is_dropped_rest_kept(store, name, value):
    store.record(module_message(layout={name: value, "good.offset": 8}))
    assert store.entries_for_agent()[KEY]["layout"] == {"good.offset": 8}


def test_layout_bounds_and_rva_suffix(store):
    layout = {"a.min": lo.LAYOUT_MIN, "a.max": lo.LAYOUT_MAX, "a.vtableRva": 0xFFFFF}
    store.record(module_message(layout=layout))
    assert store.entries_for_agent()[KEY]["layout"] == layout


def test_layout_rva_past_module_size_is_kept(store):
    # macOS: Module.size covers only __TEXT; the vtable lies in __DATA_CONST past it.
    size = module_message()["size"]
    layout = {"quiche.layout.connectionVtableRva": size + 0x4000, "a.vtableRva": lo.LAYOUT_RVA_MAX - 1}
    store.record(module_message(layout=layout))
    assert store.entries_for_agent()[KEY]["layout"] == layout


def test_named_items_are_capped(store):
    functions = {f"ns.f{i}": fn(0x1000 + i) for i in range(lo.MAX_FUNCTIONS + 5)}
    layout = {f"ns.l{i}": i for i in range(lo.MAX_LAYOUT + 5)}
    store.record(module_message(functions=functions, layout=layout))
    view = store.entries_for_agent()[KEY]
    assert len(view["functions"]) == lo.MAX_FUNCTIONS
    assert len(view["layout"]) == lo.MAX_LAYOUT


def test_merge_caps_named_items_keeping_the_newest(store, cache_path):
    old = {f"ns.old{i}": fn(0x1000 + i) for i in range(lo.MAX_FUNCTIONS)}
    store.record(module_message(functions=old, layout={f"ns.l{i}": i for i in range(lo.MAX_LAYOUT)}))
    store.record(module_message(functions={"ns.old0": fn(0x9000), "ns.new": fn(0x8000)},
                                layout={"ns.lnew": 7}))
    view = store.entries_for_agent()[KEY]
    assert len(view["functions"]) == lo.MAX_FUNCTIONS
    assert list(view["functions"])[-2:] == ["ns.old0", "ns.new"]
    assert view["functions"]["ns.old0"] == fn(0x9000) and "ns.old1" not in view["functions"]
    assert len(view["layout"]) == lo.MAX_LAYOUT and list(view["layout"])[-1] == "ns.lnew"
    assert "ns.l0" not in view["layout"]
    assert store.save()
    reloaded = LearnedOffsetsStore(cache_path, clock=FakeClock())
    reloaded.load()
    assert reloaded.entries_for_agent()[KEY] == view


def test_reload_over_the_cap_keeps_the_last_items():
    functions = {f"ns.f{i}": fn(0x1000 + i) for i in range(lo.MAX_FUNCTIONS + 5)}
    entry = lo.validate_entry(module_message(functions=functions))
    assert list(entry["functions"]) == list(functions)[-lo.MAX_FUNCTIONS:]


def test_merge_named_items_moves_updates_last_and_trims_oldest():
    merged = lo._merge_named_items({"a": 1, "b": 2, "c": 3}, {"a": 9, "d": 4}, 3)
    assert merged == {"c": 3, "a": 9, "d": 4} and list(merged) == ["c", "a", "d"]


def test_non_object_maps_are_ignored_but_rvas_keep_the_entry(store):
    key = store.record(message(functions=["x"], layout="y"))
    view = store.entries_for_agent()[key]
    assert view["rvas"] == {"SSL_read": 0x1000, "SSL_write": 0x2000}
    assert view["functions"] == {} and view["layout"] == {}


def test_bad_rvas_pair_dropped_when_named_items_exist(store):
    key = store.record(message(rvas={"SSL_read": 0x1000}, functions={"ns.f": fn(0x3000)}))
    view = store.entries_for_agent()[key]
    assert "rvas" not in view and "prologue_sha256" not in view
    assert view["functions"] == {"ns.f": fn(0x3000)}


def test_function_hash_is_lowercased(store):
    store.record(module_message(functions={"ns.f": fn(0x3000, "A" * 64)}))
    assert store.entries_for_agent()[KEY]["functions"]["ns.f"]["prologue_sha256"] == "a" * 64


def test_record_merges_per_field_in_memory(store):
    store.record(message())
    store.record(module_message(functions={"quiche.a": fn(0x3000)}, layout={"quiche.x": 1}))
    store.record(module_message(functions={"quiche.a": fn(0x5000), "boringssl.b": fn(0x6000)}))
    view = store.entries_for_agent()[KEY]
    assert view["rvas"] == {"SSL_read": 0x1000, "SSL_write": 0x2000}
    assert view["functions"] == {"quiche.a": fn(0x5000), "boringssl.b": fn(0x6000)}
    assert view["layout"] == {"quiche.x": 1}


def test_ssl_report_does_not_clobber_functions(store):
    store.record(module_message(functions={"quiche.a": fn(0x3000)}))
    store.record(message(rvas={"SSL_read": 0x7000, "SSL_write": 0x8000}))
    view = store.entries_for_agent()[KEY]
    assert view["functions"] == {"quiche.a": fn(0x3000)}
    assert view["rvas"] == {"SSL_read": 0x7000, "SSL_write": 0x8000}


def test_named_items_round_trip(store, cache_path):
    store.record(module_message(functions={"ns.f": fn(0x3000)}, layout={"ns.off": -8}))
    assert store.save()
    with open(cache_path) as fh:
        disk = json.load(fh)["entries"][KEY]
    assert "rvas" not in disk
    assert disk["functions"] == {"ns.f": fn(0x3000)} and disk["layout"] == {"ns.off": -8}
    fresh = LearnedOffsetsStore(cache_path)
    assert fresh.load() == 1
    assert fresh.entries_for_agent() == store.entries_for_agent()


def test_load_drops_bad_items_but_keeps_entry(store, cache_path):
    raw = dict(module_message(functions={"ns.f": fn(0x3000), "ns.bad": fn(0)}), last_seen=5)
    os.makedirs(os.path.dirname(cache_path))
    with open(cache_path, "w") as fh:
        json.dump({"version": 1, "entries": {KEY: raw}}, fh)
    assert store.load() == 1
    assert store.entries_for_agent()[KEY]["functions"] == {"ns.f": fn(0x3000)}


def test_merge_from_disk_is_per_field(cache_path):
    old_clock, new_clock = FakeClock(), FakeClock()
    new_clock.now = 5000.0
    quiche = LearnedOffsetsStore(cache_path, clock=new_clock)
    quiche.record(module_message(functions={"quiche.a": fn(0x3000), "shared.f": fn(0x5000)}))
    assert quiche.save()
    ssl = LearnedOffsetsStore(cache_path, clock=old_clock)  # older last_seen than the file
    ssl.record(message(functions={"shared.f": fn(0x4000), "boringssl.b": fn(0x6000)}))
    assert ssl.save()
    fresh = LearnedOffsetsStore(cache_path)
    fresh.load()
    view = fresh.entries_for_agent()[KEY]
    assert view["rvas"] == {"SSL_read": 0x1000, "SSL_write": 0x2000}
    assert view["functions"] == {"quiche.a": fn(0x3000), "shared.f": fn(0x5000),
                                 "boringssl.b": fn(0x6000)}


def test_merge_from_disk_newer_memory_wins_conflicts(cache_path):
    old_clock, new_clock = FakeClock(), FakeClock()
    new_clock.now = 5000.0
    disk = LearnedOffsetsStore(cache_path, clock=old_clock)
    disk.record(message(layout={"ns.x": 1, "ns.y": 2}))
    assert disk.save()
    ours = LearnedOffsetsStore(cache_path, clock=new_clock)
    ours.record(module_message(layout={"ns.x": 9}))
    assert ours.save()
    view = ours.entries_for_agent()[KEY]
    assert view["layout"] == {"ns.x": 9, "ns.y": 2}
    assert view["rvas"] == {"SSL_read": 0x1000, "SSL_write": 0x2000}


def test_touch_unknown_key_records_functions_only_entry(store):
    hit = module_message(functions={"ns.f": fn(0x3000)}, cache_hit=True)
    assert store.touch(hit) == KEY
    assert store.entries_for_agent()[KEY]["functions"] == {"ns.f": fn(0x3000)}


def test_entries_for_agent_named_items_are_copies(store):
    store.record(module_message(functions={"ns.f": fn(0x3000)}, layout={"ns.x": 1}))
    view = store.entries_for_agent()[KEY]
    view["functions"]["ns.f"]["rva"] = 1
    view["layout"]["ns.x"] = 2
    again = store.entries_for_agent()[KEY]
    assert again["functions"]["ns.f"]["rva"] == 0x3000 and again["layout"]["ns.x"] == 1


def test_entry_without_pair_functions_or_layout_is_rejected(store):
    assert store.record(module_message()) is None
    assert store.record(module_message(functions={"ns.f": {"rva": 0}})) is None
    assert len(store) == 0


def test_merge_from_disk_tie_keeps_ours(cache_path):
    disk = LearnedOffsetsStore(cache_path, clock=FakeClock())
    disk.record(module_message(layout={"ns.x": 1}))
    assert disk.save()
    ours = LearnedOffsetsStore(cache_path, clock=FakeClock())  # same last_seen
    ours.record(module_message(layout={"ns.x": 9}))
    assert ours.save()
    assert ours.entries_for_agent()[KEY]["layout"] == {"ns.x": 9}
