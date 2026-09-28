/*
 * mtproto_agent_harness.mjs — runs friTap's COMPILED memory-scan agent bundle
 * against a synthetic Telegram heap and proves the ported `mtproto` engine
 * recovers planted MTProto auth keys + Secret-Chat (E2E) keys.
 *
 * WHAT THIS IS. friTap's memory-scan Frida agent (agent/memory_scan_agent.ts +
 * agent/ms_agent/**) carries a new `mtproto` engine that is a byte-identical port
 * of a validated research scanner. That research scanner already has a PROVEN
 * device-free test harness at research/memory_scan_MTProto/tests/scanner_harness.js
 * which fabricates a synthetic process (a handful of Uint8Array "regions" at
 * realistic addresses, a NativePointer stand-in, and the six Frida globals the
 * scanner uses) and loads the scanner under node's `vm` module. Because friTap's
 * engine is the same code, the SAME world + sandbox exercises it.
 *
 * DIFFERENCES this harness handles (everything else is copied verbatim from the
 * research harness — copying test infrastructure is expected):
 *   1. It loads friTap's COMPILED bundle, not scanner.js. The bundle is built as
 *      a plain Node-runnable IIFE:
 *          ./node_modules/.bin/frida-compile agent/memory_scan_agent.ts \
 *              -o <tmp>.js -B iife
 *      (the default `esm` output format is NOT loadable by `vm.runInContext`;
 *      `-B iife` is). The IIFE's last statement is `rpc.exports = buildRpcExports()`,
 *      so once run inside the sandbox context it populates `ctx.rpc.exports` with
 *      the shared { configure, scanOnce, needle }.
 *   2. It uses friTap's own profile database (friTap/memory_scanning/patterns.json)
 *      and selects the profile whose engine == "mtproto" (id tgnet-android-arm64-2026).
 *      Its tier structures are identical to the research profile.
 *   3. friTap's configure() returns a DIFFERENT metadata shape than the research
 *      scanner ({ok, profileId, ranges, rangeBytes}). So this harness asserts ONLY
 *      on KEY RECOVERY — the send({type:'keylog', line, label, ...}) messages
 *      emitted by scanOnce() — never on configure() metadata.
 *
 * SHIM FIDELITY. The Ptr arithmetic, Memory.scanSync byte-matching and the
 * /proc/self/maps zero-pad handling are load-bearing and are copied UNCHANGED
 * from the research harness: the mtproto range selection depends on the
 * scudo-labelled anonymous range and on maps being indexed by NUMERIC interval
 * (the ART heap at 0x02000000 prints as "02000000" in maps but "2000000" from
 * NativePointer.toString(16)). The mtproto scan path was verified to touch only
 * the API surface this shim already provides (Process.enumerateRanges/
 * enumerateModules/findRangeByAddress/pointerSize/setExceptionHandler,
 * Memory.scanSync, File.readAllText, Checksum.compute, ptr, send, and the Ptr
 * methods add/sub/and/compare/equals/isNull/readByteArray/readPointer/readS32/
 * readU32/toString) — so no shim adaptation beyond the loader was required.
 *
 * Usage:   node tests/agent/mtproto_agent_harness.mjs
 * Exit:    0 on PASS, non-zero on FAIL. A one-line-per-key summary and a final
 *          PASS/FAIL banner (with recovered auth-key + e2e-key counts) go to
 *          stdout; agent diagnostics go to stderr.
 */
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import vm from 'node:vm';
import nodeCrypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
/* tests/agent/ -> project root is two levels up. */
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const PATTERNS_PATH = path.join(PROJECT_ROOT, 'friTap', 'memory_scanning', 'patterns.json');
const AGENT_ENTRY = path.join(PROJECT_ROOT, 'agent', 'memory_scan_agent.ts');
const FRIDA_COMPILE = path.join(PROJECT_ROOT, 'node_modules', '.bin', 'frida-compile');

/* ---------------------------------------------------------------------------
 * Base addresses.
 *
 * looksLikeHeapPointer() rejects anything below validators.pointer_min and
 * untag() masks off the ARM64 top byte, so the native heap has to live at a
 * realistic 39-bit userspace address or the agent would refuse every pointer we
 * plant for reasons that have nothing to do with the behaviour under test.
 *
 * ART_BASE is 0x02000000 DELIBERATELY. That is the real dalvik-main space base
 * on the measured device and it is the ONE address in the process whose hex
 * form has a leading zero: /proc/self/maps prints it "02000000" (the kernel
 * pads to a minimum of eight hex digits) while NativePointer.toString(16)
 * prints "2000000". A name lookup keyed by hex STRING therefore silently drops
 * the whole ART heap — and with it every Secret-Chat key. The agent indexes
 * maps by NUMERIC interval instead; this base is what proves it.
 * ------------------------------------------------------------------------- */
const ART_BASE = 0x02000000n;
/* ...but a scenario may move it above 4 GiB. That is not a variant for its own
 * sake: the ART back-reference is a 32-bit truncation of the object address, so
 * a heap mapped above 4 GiB makes the truncation AMBIGUOUS and the check
 * inapplicable — which the agent has to report as a skipped check with a reason,
 * never as a round trip that failed. There is no other way to reach that branch,
 * and "inapplicable" quietly reading as "failed" is exactly the kind of wrong
 * diagnosis this suite exists to catch. */
function artBaseOf(scenario) {
    return scenario.art_base === undefined ? ART_BASE : BigInt(scenario.art_base);
}
const ART_SIZE = 0x20000;
const SCUDO_BASE = 0x7000000000n;
const SCUDO_SIZE = 0x10000;
const SCUDO_AGENT_BASE = 0x7300000000n;   // allowlisted BY NAME, excluded by address
const SCUDO_AGENT_SIZE = 0x2000;
const MODULE_BASE = 0x7100000000n;        // file-backed: require_anonymous drops it
const MODULE_SIZE = 0x1000;
const UNNAMED_BASE = 0x7400000000n;       // anonymous rw- but matches no name list
const UNNAMED_SIZE = 0x1000;

const MASK64 = (1n << 64n) - 1n;

/* Filler bytes. Chosen so that no aligned int32 made of them lands in
 * [dc_id_min, dc_id_max] (0xaaaaaaaa and 0xbbbbbbbb both read as negative
 * int32) and so that they can never contribute to an anchor, every one of which
 * contains a 0x00 byte. */
const NATIVE_FILLER = 0xaa;
const ART_FILLER = 0xbb;

/* An ART byte[] header's class word. Non-zero (a zero klass would be a free
 * slot) and free of 0x00 bytes, so it cannot extend an anchor match. */
const ART_KLASS = 0x70315a68;

/* ---------------------------------------------------------------------------
 * Memory model
 * ------------------------------------------------------------------------- */

class Region {
    constructor(name, base, size, options) {
        const opts = options || {};
        this.name = name;
        this.base = base;                       // BigInt
        this.size = size;                       // Number
        this.bytes = new Uint8Array(size);
        this.enumerated = opts.enumerated !== false;
        this.file = opts.file || null;          // set => the range is file-backed
        this.mapsName = opts.mapsName || null;  // the kernel's [anon:...] label
        if (opts.fill) this.bytes.fill(opts.fill);
    }

    end() { return this.base + BigInt(this.size); }

    holds(address, length) {
        return address >= this.base && address + BigInt(length) <= this.end();
    }
}

class Memspace {
    constructor() { this.regions = []; }

    add(region) { this.regions.push(region); return region; }

    locate(address, length) {
        for (const r of this.regions) if (r.holds(address, length)) return r;
        return null;
    }

    read(address, length) {
        const region = this.locate(address, length);
        /* Load-bearing: every read in the agent goes through a try/catch wrapper
         * that turns a fault into null, and several decisions turn on the
         * difference between "read returned null" and "read threw". A stub that
         * quietly returned zeroes for unmapped memory would delete that branch.
         * So: throw, exactly as Frida does. */
        if (region === null) {
            throw new Error('access violation accessing 0x' + address.toString(16));
        }
        const start = Number(address - region.base);
        return region.bytes.subarray(start, start + length);
    }

    write(address, bytes) {
        const region = this.locate(address, bytes.length);
        if (region === null) {
            throw new Error('write outside the synthetic process at 0x' + address.toString(16));
        }
        region.bytes.set(bytes, Number(address - region.base));
    }
}

/* ---------------------------------------------------------------------------
 * The pointer object (Frida's NativePointer)
 * ------------------------------------------------------------------------- */

function toBig(value) {
    if (value instanceof Ptr) return value.value;
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') return BigInt(Math.trunc(value));
    if (typeof value === 'string') {
        const text = value.trim();
        return BigInt(/^0[xX]/.test(text) ? text : (/^[0-9]+$/.test(text) ? text : '0x' + text));
    }
    throw new TypeError('cannot convert ' + typeof value + ' to a pointer');
}

class Ptr {
    constructor(mem, value) {
        this.mem = mem;
        this.value = value & MASK64;
    }

    /* Arithmetic wraps at 64 bits, as the real thing does. */
    add(v) { return new Ptr(this.mem, this.value + toBig(v)); }
    sub(v) { return new Ptr(this.mem, this.value - toBig(v)); }
    and(v) { return new Ptr(this.mem, this.value & toBig(v)); }
    /* Tier E's pointerToScanNeedle() shifts the vtable pointer a byte at a time to
     * render it as a scan pattern; the mtproto engine used no shift before Tier E
     * was enabled, so the shim never needed one. */
    shr(v) { return new Ptr(this.mem, (this.value >> toBig(v)) & MASK64); }

    compare(v) {
        const other = toBig(v);
        return this.value < other ? -1 : (this.value > other ? 1 : 0);
    }

    equals(v) { return this.value === toBig(v); }
    isNull() { return this.value === 0n; }

    /* Two callers, two formats, and getting this wrong is silent:
     *   - addressToNumber() does parseInt(p.toString(16), 16), which would
     *     happily accept "0x7000001000" and return 0 (parseInt stops at 'x');
     *   - everywhere else the agent concatenates the pointer into a message,
     *     which calls toString() with no argument and wants the 0x form. */
    toString(radix) {
        if (radix === undefined) return '0x' + this.value.toString(16);
        /* Tier E renders needle bytes via .and(0xff).toString(10); any explicit
         * radix must produce the bare number in that base, NOT the 0x form (which
         * parseInt(_, 10) would silently read as 0). */
        return this.value.toString(radix);
    }

    readPointer() {
        const b = this.mem.read(this.value, 8);
        let v = 0n;
        for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);   // little-endian
        return new Ptr(this.mem, v);
    }

    /* UNSIGNED single byte and little-endian u16. The mtproto engine reads only
     * 32-bit fields, so these were unused; the boringssl engine reads InplaceVector
     * length bytes (readU8OrNull) and SSL_SESSION.ssl_version (readU16OrNull), so it
     * needs both. */
    readU8() {
        return this.mem.read(this.value, 1)[0];
    }

    readU16() {
        const b = this.mem.read(this.value, 2);
        return (b[0] | (b[1] << 8)) & 0xffff;
    }

    readS32() {
        const b = this.mem.read(this.value, 4);
        const u = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
        return u | 0;                                                // sign-extend
    }

    /* UNSIGNED, and a separate method rather than a flag, because the agent
     * chooses between the two: a compressed ART reference is compared against
     * the low 32 bits of an address and must not come back sign-extended. */
    readU32() {
        const b = this.mem.read(this.value, 4);
        return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
    }

    readByteArray(length) {
        /* Frida hands back an ArrayBuffer and the agent wraps it in a
         * Uint8Array; a copy, not a view, so a later write cannot retroactively
         * change bytes the agent has already decided about. */
        return this.mem.read(this.value, length).slice().buffer;
    }

    writePointer(p) {
        let v = toBig(p);
        const out = new Uint8Array(8);
        for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
        this.mem.write(this.value, out);
        return this;
    }
}

/* ---------------------------------------------------------------------------
 * Deterministic key material
 *
 * The profile's validators are a WINDOW, not a floor, so filler will not do and
 * neither will anything too good: a candidate needs entropy in
 * [min_shannon_entropy_bits, max_shannon_entropy_bits] and a distinct-byte
 * count in [min_distinct_bytes, max_distinct_bytes]. Uniform random bytes land
 * squarely inside both, which is exactly what was measured of real 2048-bit
 * MTProto keys — so that is what this generates, from a name-seeded xorshift so
 * a given key holds the same bytes on every run and the tests can compare hex.
 *
 * Byte 0x00 is excluded on purpose. Every anchor in the profile contains a 0x00
 * byte, so a key that cannot contain one cannot accidentally BE an anchor, and
 * the hit accounting stays exact rather than merely probable. (max_zero_fraction
 * is an upper bound, so zero zeros is inside the window.)
 * ------------------------------------------------------------------------- */

function xorshift(seed) {
    let s = 0x9e3779b9;
    for (let i = 0; i < seed.length; i++) {
        s = Math.imul(s ^ seed.charCodeAt(i), 0x85ebca6b) >>> 0;
    }
    if (s === 0) s = 1;
    return function next() {
        s ^= s << 13; s >>>= 0;
        s ^= s >>> 17;
        s ^= s << 5; s >>>= 0;
        return s;
    };
}

function hexOf(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s;
}

/* The same three numbers the agent's byteStats() computes, so the harness can
 * refuse to plant material the agent would reject for an uninteresting reason. */
function byteStats(u8) {
    const counts = new Array(256).fill(0);
    for (let i = 0; i < u8.length; i++) counts[u8[i]]++;
    let bits = 0, distinct = 0;
    for (let i = 0; i < 256; i++) {
        if (counts[i] === 0) continue;
        distinct++;
        const p = counts[i] / u8.length;
        bits -= p * (Math.log(p) / Math.LN2);
    }
    return { bits: bits, distinct: distinct, zeros: counts[0] / u8.length };
}

function insideWindow(stats, validators) {
    return stats.bits >= validators.min_shannon_entropy_bits &&
           stats.bits <= validators.max_shannon_entropy_bits &&
           stats.distinct >= validators.min_distinct_bytes &&
           stats.distinct <= validators.max_distinct_bytes &&
           stats.zeros <= validators.max_zero_fraction;
}

function sha1Hex(bytes) {
    return nodeCrypto.createHash('sha1').update(Buffer.from(bytes)).digest('hex');
}

/* A key plus the id the central oracle derives from it. Reseeded until BOTH
 * hold: the blob sits inside the validator window, and its id contains no 0x00
 * byte — the id gets planted in scanned memory, and an id with a zero in it
 * could extend into an anchor match and muddy the hit counts. */
function makeKey(name, length, validators, idLen) {
    for (let attempt = 0; attempt < 512; attempt++) {
        const next = xorshift(attempt === 0 ? name : name + '#' + attempt);
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) bytes[i] = (next() % 255) + 1;
        const stats = byteStats(bytes);
        if (!insideWindow(stats, validators)) continue;
        const digest = sha1Hex(bytes);
        const id = digest.slice(-idLen * 2);
        let hasZeroByte = false;
        for (let i = 0; i < idLen; i++) {
            if (parseInt(id.slice(i * 2, i * 2 + 2), 16) === 0) hasZeroByte = true;
        }
        if (hasZeroByte) continue;
        return { bytes: bytes, hex: hexOf(bytes), digest: digest, id: id, seed: name };
    }
    throw new Error('could not synthesise key material inside the profile window for ' + name);
}

/* A 256-byte AES S-box: a PERMUTATION of 0..255. It scores a perfect 8.000 bits
 * with 256 distinct values and a floor-only gate passes it — which is the whole
 * reason the profile states a ceiling. Deterministic Fisher-Yates so the blob is
 * the same on every run. A permutation contains each byte exactly once, so it
 * cannot contain any anchor (every anchor has two or more 0x00 bytes). */
function makeSbox(seed) {
    const next = xorshift(seed);
    const out = new Uint8Array(256);
    for (let i = 0; i < 256; i++) out[i] = i;
    for (let i = 255; i > 0; i--) {
        const j = next() % (i + 1);
        const t = out[i]; out[i] = out[j]; out[j] = t;
    }
    return out;
}

/* Structured, low-entropy filler: the ordinary false positive an entropy FLOOR
 * is there to reject. 16 distinct values, 4.000 bits. */
function makeLowEntropy(length) {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = (i % 16) + 1;
    return out;
}

/* A blob with an EXACT distinct-byte count, for testing the distinct WINDOW's
 * boundary rather than its middle.
 *
 * A ramp of `distinct` values repeated to `length` gives the flattest histogram
 * those two numbers allow: with 256 bytes over 132 values, 124 values appear
 * twice and 8 appear once, which scores 7.031 bits — comfortably inside the
 * entropy window. That is deliberate. The point of a D=131 vs D=132 pair is that
 * the distinct FLOOR is the only thing that can separate them; if the entropy
 * floor rejected one of them too, the test would pass for the wrong reason.
 * Byte 0x00 never appears, so max_zero_fraction cannot interfere either, and no
 * anchor (every one of which contains a 0x00) can form inside the blob. */
function makeExactDistinct(distinct, length) {
    if (distinct < 1 || distinct > 255 || distinct > length) {
        throw new Error('cannot build a ' + length + '-byte blob with ' +
                        distinct + ' distinct non-zero bytes');
    }
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = (i % distinct) + 1;
    return out;
}

/* ---------------------------------------------------------------------------
 * Scenario -> synthetic process
 * ------------------------------------------------------------------------- */

function align(value, to) { return value + ((to - (value % to)) % to); }

/* Address arithmetic by a SIGNED profile offset. Several EncryptedChat offsets
 * are negative — the object's reference slots sit ahead of the field the scan
 * finds — and BigInt(-60) is exactly what a subtraction needs, so this is one
 * line; it exists to make the sign explicit at every call site. */
function shiftBig(address, delta) { return address + BigInt(delta); }

function u32le(value) {
    return Uint8Array.from([value & 0xff, (value >>> 8) & 0xff,
                            (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
}

/* Little-endian u16, for the BoringSSL min_version||max_version anchor. */
function u16le(value) {
    return Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
}

/* ---------------------------------------------------------------------------
 * BoringSSL secret material.
 *
 * The boringssl profile's validators are a FLOOR-and-ceiling on length plus an
 * entropy floor and a zero-fraction ceiling (looksLikeSecret / looksLikeRandom in
 * agent/ms_agent/core/heuristics.ts) — no distinct-byte or max-entropy window like
 * mtproto's, so makeKey() cannot be reused (it reads window keys the boringssl
 * profile does not carry). Non-zero xorshift bytes clear every gate: zero zeros is
 * inside max_zero_fraction, and ~5-8 bits of entropy clears the 4.0-bit floor.
 * Name-seeded so a given secret holds the same bytes on every run and the test can
 * compare hex. Byte 0x00 is excluded so a secret can never contain an anchor byte. */
function makeSecretBytes(name, length) {
    const next = xorshift(name);
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = (next() % 255) + 1;
    return out;
}

function bytesFromHex(h) {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    return out;
}

const DEFAULT_GROUPS = [{ dc_id: 2, slots: 3 }, { dc_id: 4, slots: 2 }];

function buildWorld(scenario, profile) {
    const off = profile.struct_offsets;
    const constants = profile.constants;
    const validators = profile.validators;
    const tierA = profile.tiers.A_bytearray_authkey;
    const tierB = profile.tiers.B_authkeyid_roundtrip;
    const tierC = profile.tiers.C_art_secretchat_key;

    const keyLen = constants.auth_key_len;
    const idLen = constants.auth_key_id_len;
    const stride = off.DatacenterKeySlot.stride;

    const mem = new Memspace();
    const scudo = mem.add(new Region('scudo', SCUDO_BASE, SCUDO_SIZE, {
        mapsName: '[anon:scudo:primary]', fill: NATIVE_FILLER
    }));
    const artBase = artBaseOf(scenario);
    const art = mem.add(new Region('art', artBase, ART_SIZE, {
        mapsName: '[anon:dalvik-main space]', fill: ART_FILLER
    }));
    /* File-backed, so scan_regions.require_anonymous keeps it out of the native
     * scan, and its path matches no allowlist, so Tier C skips it too. */
    mem.add(new Region('module', MODULE_BASE, MODULE_SIZE, {
        file: { path: '/data/app/org.telegram.messenger/lib/arm64/libtmessages.49.so' }
    }));
    /* Anonymous rw-, in no list at all: proof that selectRanges() returns the
     * ALLOWLIST and not simply "everything eligible". */
    mem.add(new Region('unnamed', UNNAMED_BASE, UNNAMED_SIZE, { fill: NATIVE_FILLER }));
    /* Named so the allowlist DOES match it, but overlapped by a frida module.
     * The address-based agent-owned exclusion is therefore the only thing that
     * can drop it — which is exactly the claim the agent makes about why that
     * exclusion cannot be left to name_denylist. Turning off `agent_module`
     * removes the module and the very same range comes back into scope. */
    mem.add(new Region('scudo_agent', SCUDO_AGENT_BASE, SCUDO_AGENT_SIZE, {
        mapsName: '[anon:scudo:secondary]', fill: NATIVE_FILLER
    }));
    const agentModule = scenario.agent_module !== false;

    const blobs = {};   // name -> {address, length} for mid-run mutation
    const planted = {
        auth_keys: [], secret_chats: [], rejected: [], probes: [], groups: [],
        art_base_maps: null, art_base_pointer: art.base.toString(16),
        scudo_base: '0x' + SCUDO_BASE.toString(16),
        anchors: { tier_a: tierA.anchors.map((a) => a.pattern),
                   tier_c: tierC.anchors.map((a) => a.pattern) }
    };

    function writeAt(address, bytes) { mem.write(address, bytes); }
    function writePointerAt(address, value) { new Ptr(mem, address).writePointer(value); }

    // --- native object area -------------------------------------------------
    /* ByteArray{length@0 == key_len, bytes*@8} immediately followed by its key.
     * Both are taken from struct_offsets, never written down. */
    let objectCursor = align(0x800 + (scenario.groups || DEFAULT_GROUPS).length * 0x400, 16);

    function plantByteArray(name, bytes) {
        const byteArrayAddress = SCUDO_BASE + BigInt(objectCursor);
        const keyAddress = byteArrayAddress + BigInt(off.ByteArray.size);
        objectCursor = align(objectCursor + off.ByteArray.size + bytes.length, 16);
        if (objectCursor > SCUDO_SIZE) throw new Error('synthetic native heap too small');

        const header = new Uint8Array(off.ByteArray.size);
        header.set(u32le(bytes.length), off.ByteArray.length);
        writeAt(byteArrayAddress, header);
        writePointerAt(byteArrayAddress + BigInt(off.ByteArray.bytes), keyAddress);
        writeAt(keyAddress, bytes);
        blobs[name] = { address: keyAddress, length: bytes.length };
        return { byteArray: byteArrayAddress, key: keyAddress };
    }

    // --- Datacenter objects and their key slots -----------------------------
    /* A Datacenter's own id sits somewhere ahead of its key slots and
     * probeDatacenterId() walks backwards, nearest first, for an aligned int32
     * in [dc_id_min, dc_id_max]. So: the id goes DC_ID_BACK bytes before the
     * first slot with nothing but filler in between, and consecutive groups are
     * spaced further apart than dc_id_probe_window so that one group's probe can
     * never reach the previous group's id. Both distances come from the
     * profile. */
    const DC_ID_BACK = 64;
    const groupSpacing = align(tierB.dc_id_probe_window + 256, 64);
    const groups = scenario.groups || DEFAULT_GROUPS;

    groups.forEach(function (group, g) {
        const origin = 0x200 + g * groupSpacing;
        const dcIdAddress = SCUDO_BASE + BigInt(origin);
        const slotsBase = SCUDO_BASE + BigInt(origin + DC_ID_BACK);
        writeAt(dcIdAddress, u32le(group.dc_id));
        const slotAddresses = [];

        for (let s = 0; s < group.slots; s++) {
            const name = 'g' + g + 's' + s;
            const key = makeKey(name, keyLen, validators, idLen);
            const placed = plantByteArray(name, key.bytes);
            const slot = slotsBase + BigInt(s * stride);
            slotAddresses.push('0x' + slot.toString(16));

            const back = (group.break_roundtrip === true ||
                          (group.break_roundtrip || []).indexOf(s) !== -1)
                /* A plausible but WRONG back pointer: the round trip is what
                 * confirms a key, so breaking it must demote the candidate to
                 * unpaired rather than emit it. */
                ? placed.key
                : placed.byteArray;
            writePointerAt(slot + BigInt(off.DatacenterKeySlot.byte_array_ptr), back);
            writeAt(slot + BigInt(off.DatacenterKeySlot.auth_key_id), bytesFromHex(key.id));

            const role = tierB.slot_roles[s] || tierB.slot_roles[tierB.slot_roles.length - 1];
            planted.auth_keys.push({
                name: name, group: g, slot_index: s, role: role,
                key_type: tierB.role_keylog_key_type[role],
                dc_id: group.dc_id, id: key.id, hex: key.hex,
                byte_array: '0x' + placed.byteArray.toString(16),
                key_addr: '0x' + placed.key.toString(16),
                slot_addr: '0x' + slot.toString(16),
                roundtrip_broken: back !== placed.byteArray
            });
        }
        planted.groups.push({ dc_id: group.dc_id, slots: slotAddresses });
    });

    // --- decoys in the same heap -------------------------------------------
    if (scenario.sbox !== false) {
        const bytes = makeSbox('aes-sbox');
        const placed = plantByteArray('sbox', bytes);
        const stats = byteStats(bytes);
        planted.rejected.push({
            name: 'sbox', hex: hexOf(bytes), entropy: stats.bits, distinct: stats.distinct,
            byte_array: '0x' + placed.byteArray.toString(16),
            key_addr: '0x' + placed.key.toString(16)
        });
    }
    if (scenario.low_entropy !== false) {
        const bytes = makeLowEntropy(keyLen);
        const placed = plantByteArray('low_entropy', bytes);
        const stats = byteStats(bytes);
        planted.rejected.push({
            name: 'low_entropy', hex: hexOf(bytes), entropy: stats.bits,
            distinct: stats.distinct,
            byte_array: '0x' + placed.byteArray.toString(16),
            key_addr: '0x' + placed.key.toString(16)
        });
    }

    // --- ART byte[] Secret-Chat keys and their EncryptedChat objects --------
    /* ArtByteArray{klass u32 @0, monitor u32 @4, length u32 @8, data @12}. The
     * anchor is monitor(0)+length(key_len) and the profile says it sits
     * anchor_offset_in_struct into the object, so planting the object IS
     * planting the anchor.
     *
     * A chat may be planted as SEVERAL COPIES. That is not a synthetic
     * convenience: Android's concurrent mark-compact collector keeps the object
     * graph at two addresses at once, each EncryptedChat copy references the
     * byte[] next to IT, and so a fingerprint scan returns one site per copy.
     * Each site closes against its own copy's base and no other, which is the
     * pairing the agent has to get right — and got wrong, on device, by holding
     * one base while the scan returned two sites.
     *
     * Everything about WHERE things go comes from the profile: the header
     * layout, the anchor offset, the key-data candidate offsets and the
     * back-reference candidate offsets. The only literals are the slot origins
     * and strides, which are arbitrary addresses by construction.
     * ---------------------------------------------------------------------- */
    const artOff = off.ArtByteArray;
    const chatOff = off.EncryptedChat;
    const dataOffsets = tierC.key_data_offset_candidates_from_anchor ||
                        [tierC.key_data_offset_from_anchor];
    /* auth_key_ref_candidates is the only spelling the agent reads. A profile
     * without it is a build nobody has derived the back-reference for: there is
     * nowhere to plant a reference, and configure() refuses it. */
    const refOffsets = chatOff.auth_key_ref_candidates || [];
    const chats = scenario.secret_chats === undefined
        ? [{ chat_id: 424242 }] : scenario.secret_chats;

    /* byte[] objects low, then decoy fingerprint sites, then the real ones. The
     * decoys sit at LOWER addresses on purpose: Memory.scanSync returns hits in
     * address order, so a decoy planted here is sites[0] and the agent has to
     * prefer a site that actually closes over the first one it was handed. */
    const OBJECT_ORIGIN = 0x100, OBJECT_STRIDE = 0x800;
    const DECOY_ORIGIN = 0x6000, SITE_ORIGIN = 0x8000, SITE_STRIDE = 0x400;
    let objectSlot = 0, siteSlot = 0, decoySlot = 0;

    function low32(address) { return Number(address & 0xffffffffn); }

    /* The four shapes a back-reference can take on the wire. "poisoned" is the
     * negation an ART built with heap poisoning stores; "wrong" is a plausible
     * value that is not any object's base, which is what a fingerprint copy in a
     * serialisation buffer looks like from the agent's side. */
    function referenceValue(mode, target) {
        if (mode === 'poisoned') return Number((0x100000000n - BigInt(low32(target))) & 0xffffffffn);
        if (mode === 'wrong') return low32(target) + 0x11;   // misaligned, no object there
        return low32(target);
    }

    chats.forEach(function (chat, i) {
        const name = 'e2e' + i;
        const key = makeKey(name, tierC.key_len, validators, idLen);
        const copies = chat.copies === undefined ? 1 : chat.copies;
        const dataOffset = dataOffsets[chat.data_offset_index || 0];
        const refOffset = refOffsets[chat.ref_offset_index || 0];
        const refMode = chat.ref || 'raw';

        /* Planting the key at a LATER candidate means the earlier candidate has
         * to read something that fails the entropy gate, or it would shadow the
         * later one and the fixture would be testing nothing. That is only
         * possible when the two windows do not overlap — 8 and 12 share 252 of
         * their 256 bytes, so no filler can separate them. Refusing loudly here
         * is the executable form of that limitation. */
        const firstOffset = dataOffsets[0];
        if (dataOffset !== firstOffset && dataOffset - firstOffset < tierC.key_len) {
            throw new Error('data_offset_index ' + (chat.data_offset_index || 0) +
                ' (offset ' + dataOffset + ') overlaps candidate ' + firstOffset +
                ': the two ' + tierC.key_len + '-byte windows share ' +
                (tierC.key_len - (dataOffset - firstOffset)) + ' bytes, so the entropy ' +
                'gate cannot tell them apart and the earlier candidate always wins');
        }

        const bases = [], keyAddresses = [];
        for (let c = 0; c < copies; c++) {
            const objectAddress = artBase + BigInt(OBJECT_ORIGIN + (objectSlot++) * OBJECT_STRIDE);
            const anchor = objectAddress + BigInt(tierC.anchor_offset_in_struct);
            const keyAddress = anchor + BigInt(dataOffset);
            const header = new Uint8Array(artOff.data);
            header.set(u32le(ART_KLASS), artOff.klass);
            header.set(u32le(0), artOff.monitor);
            header.set(u32le(key.bytes.length), artOff.length);
            writeAt(objectAddress, header);
            /* What the FIRST candidate offset would read, when the key is not
             * there: structured filler, so that candidate fails the gate and the
             * scan has to walk on to the next one. */
            if (dataOffset !== firstOffset) {
                writeAt(anchor + BigInt(firstOffset), makeLowEntropy(tierC.key_len));
            }
            writeAt(keyAddress, key.bytes);
            blobs[c === 0 ? name : name + '#' + c] =
                { address: keyAddress, length: key.bytes.length };
            bases.push(objectAddress);
            keyAddresses.push(keyAddress);
        }

        /* The EncryptedChat objects. Their offsets are stated relative to
         * key_fingerprint, because that field is what the scan actually finds. */
        const sites = [], siteChatIds = [];
        let decoySite = null;
        if (chat.confirm !== false) {
            if (chat.decoy_site !== undefined) {
                /* A copy of the fingerprint with no object behind it — the
                 * serialisation-buffer case. Its chat_id is deliberately a
                 * different number: an agent that reads chat_id from sites[0]
                 * without checking emits THIS one, and the test can see it. */
                decoySite = artBase + BigInt(DECOY_ORIGIN + (decoySlot++) * SITE_STRIDE);
                writeAt(decoySite + BigInt(chatOff.key_fingerprint), bytesFromHex(key.id));
                writeAt(shiftBig(decoySite, chatOff.chat_id), u32le(chat.decoy_site.chat_id));
            }
            for (let c = 0; c < copies; c++) {
                const site = artBase + BigInt(SITE_ORIGIN + (siteSlot++) * SITE_STRIDE);
                const chatId = (chat.copy_chat_ids || [])[c] === undefined
                    ? chat.chat_id : chat.copy_chat_ids[c];
                writeAt(site + BigInt(chatOff.key_fingerprint), bytesFromHex(key.id));
                writeAt(shiftBig(site, chatOff.chat_id), u32le(chatId));
                /* pair_order 'reverse' makes site c reference the OTHER copy's
                 * byte[]. Every site still closes — against a different base —
                 * so an agent that pairs site i with base i positionally reports
                 * "neither closed", which is exactly the defect this reproduces. */
                const target = chat.pair_order === 'reverse'
                    ? bases[copies - 1 - c] : bases[c];
                if (refMode !== 'none' && refOffset !== undefined) {
                    writeAt(shiftBig(site, refOffset), u32le(referenceValue(refMode, target)));
                }
                sites.push(site);
                siteChatIds.push(chatId);
            }
        }

        planted.secret_chats.push({
            name: name, chat_id: chat.chat_id, fingerprint: key.id, hex: key.hex,
            copies: copies, ref_mode: refMode,
            ref_offset: refOffset === undefined ? null : refOffset,
            data_offset: dataOffset, pair_order: chat.pair_order || 'same',
            art_object: '0x' + bases[0].toString(16),
            art_objects: bases.map((b) => '0x' + b.toString(16)),
            key_addr: '0x' + keyAddresses[0].toString(16),
            key_addrs: keyAddresses.map((a) => '0x' + a.toString(16)),
            fingerprint_site: sites.length === 0 ? null : '0x' + sites[0].toString(16),
            fingerprint_sites: sites.map((s) => '0x' + s.toString(16)),
            site_chat_ids: siteChatIds,
            decoy_site: decoySite === null ? null : '0x' + decoySite.toString(16),
            decoy_chat_id: decoySite === null ? null : chat.decoy_site.chat_id,
            confirmed: chat.confirm !== false
        });
    });

    // --- blobs with an exact distinct-byte count ----------------------------
    /* Planted as ordinary native ByteArrays, so they travel the normal Tier A
     * funnel and are visible in exactly the way a real candidate would be. */
    (scenario.distinct_probes || []).forEach(function (distinct) {
        const bytes = makeExactDistinct(distinct, constants.auth_key_len);
        const probeName = 'distinct' + distinct;
        const placed = plantByteArray(probeName, bytes);
        const stats = byteStats(bytes);
        planted.probes.push({
            name: probeName, distinct_requested: distinct, hex: hexOf(bytes),
            entropy: stats.bits, distinct: stats.distinct, zeros: stats.zeros,
            byte_array: '0x' + placed.byteArray.toString(16),
            key_addr: '0x' + placed.key.toString(16)
        });
    });

    return { mem: mem, blobs: blobs, planted: planted, art: art, scudo: scudo,
             agentModule: agentModule };
}

/* ---------------------------------------------------------------------------
 * /proc/self/maps
 *
 * THE trap this file exists to pin down. The kernel prints a mapping's start
 * and end with a MINIMUM WIDTH of eight hex digits, so the ART heap at
 * 0x02000000 appears as "02000000" — while NativePointer.toString(16) renders
 * the very same address as "2000000". Anything that keys a name lookup by that
 * string drops the one region holding every Secret-Chat key.
 *
 * This function therefore reproduces the kernel's padding rather than Frida's
 * formatting, and the pytest side asserts the two really do differ before it
 * asserts that the key is found anyway.
 * ------------------------------------------------------------------------- */

function mapsAddress(value) {
    const text = value.toString(16);
    return text.length < 8 ? text.padStart(8, '0') : text;
}

function buildMapsText(mem, planted) {
    const lines = [];
    for (const region of mem.regions) {
        if (!region.enumerated) continue;
        const label = region.file !== null ? region.file.path
                    : (region.mapsName === null ? '' : region.mapsName);
        const start = mapsAddress(region.base);
        if (region.name === 'art') planted.art_base_maps = start;
        lines.push(start + '-' + mapsAddress(region.end()) +
                   ' rw-p 00000000 00:00 0    ' + label);
    }
    /* Noise the agent must survive: a header-ish line that does not parse, and a
     * named mapping neither list cares about. */
    lines.push('this line is not a maps entry');
    lines.push('7f1000000000-7f1000001000 r-xp 00000000 fd:00 1234    /system/lib64/libc.so');
    return lines.join('\n') + '\n';
}

/* ---------------------------------------------------------------------------
 * The stub Frida globals
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * The virtual clock — opt-in, per scenario.
 *
 * Tier C's primary throttle is wall-clock time elapsed since the last pass
 * COMPLETED, and the only honest way to test "the pass 20 s later runs" is to
 * MOVE time rather than to spend it: sleeping twenty seconds in a unit test is
 * not a test, it is a delay, and it would make the suite's runtime a function of
 * a profile value.
 *
 * The agent reads the clock through Date.now() and nowhere else, so a settable
 * now() is the whole of it. Absent scenario.clock the sandbox gets no Date key
 * at all and the vm context keeps its own real one, which is what keeps
 * stats.durationMs a real measurement everywhere else.
 * ------------------------------------------------------------------------- */

function buildClock(scenario) {
    if (!scenario.clock) return null;
    const advance = scenario.clock.advance_before || {};
    return {
        now: scenario.clock.start === undefined ? 1000000000000 : scenario.clock.start,
        history: [],
        advanceBefore(pass) { this.now += advance[String(pass)] || 0; this.history.push(this.now); }
    };
}

function buildSandbox(world, profile, forcedDigests, clock, processPointerSize) {
    const mem = world.mem;
    const sent = [];
    const mapsText = buildMapsText(mem, world.planted);

    function rangeObject(region) {
        const range = { base: new Ptr(mem, region.base), size: region.size, protection: 'rw-' };
        /* require_anonymous tests `r.file`, so a file key must be ABSENT, not
         * null, on an anonymous range. */
        if (region.file !== null) range.file = region.file;
        return range;
    }

    /* A frida module laid exactly over the allowlisted 'scudo:secondary' range,
     * so buildAgentOwnedRanges() has something to find and isAgentOwnedRange()
     * has to be the thing that drops it. */
    const modules = [{
        name: 'libtmessages.49.so',
        path: '/data/app/org.telegram.messenger/lib/arm64/libtmessages.49.so',
        base: new Ptr(mem, MODULE_BASE), size: MODULE_SIZE
    }];
    if (world.agentModule) {
        modules.push({
            name: 'frida-agent-64.so', path: '/data/local/tmp/re.frida.server/frida-agent-64.so',
            base: new Ptr(mem, SCUDO_AGENT_BASE), size: SCUDO_AGENT_SIZE
        });
    }

    const exceptionHandlers = [];

    const Process = {
        /* The synthetic heap is laid out from the profile's own offsets, so the
         * stub process agrees with the profile by construction - which is the
         * right default and also means a scenario cannot test configure()'s
         * pointer-width refusal by patching the profile, because patching it
         * moves BOTH sides. `process_pointer_size` overrides only this side: it
         * is how a scenario says "the profile is the shipped arm64 one and the
         * target is 32-bit", which is the mismatch the check exists for. */
        pointerSize: processPointerSize === undefined
            ? profile.match.pointer_size : processPointerSize,

        /* The agent asks twice with different protections — the tier's own
         * protection for the scan, and '---' for the mapped-address snapshot,
         * where '---' means "every mapping". The synthetic process has only rw-
         * mappings, so both answers are the same set. */
        enumerateRanges: function () {
            return mem.regions.filter((r) => r.enumerated).map(rangeObject);
        },

        enumerateModules: function () { return modules.slice(); },

        /* Only reachable before the first scanOnce() installs the snapshot.
         * Implemented so the fallback in isMappedAddress() is not a lie. */
        findRangeByAddress: function (p) {
            const address = toBig(p);
            for (const r of mem.regions) {
                if (r.enumerated && address >= r.base && address < r.end()) return rangeObject(r);
            }
            return null;
        },

        /* There are no native threads here to fault, so the handler is captured
         * rather than installed: a scenario's `native_faults` count fires it
         * directly, which is the only way to prove the counter the handler feeds
         * actually reaches the stats block the driver reads. */
        setExceptionHandler: function (handler) { exceptionHandlers.push(handler); },

        /* The boringssl engine consults these two when it derives / resolves its
         * Tier B needle (rememberNeedle() and resolveNeedleValue() in
         * agent/ms_agent/engines/boringssl/index.ts); the mtproto engine never
         * touches them. Returning null is the honest answer for a synthetic heap
         * with no real modules behind its pointers: rememberNeedle() still records
         * the needle VALUE (module/rva just come back null), and resolveNeedleValue()
         * falls back to that derived value, so Tier B works while the profile's
         * build-specific RVA hint resolves to nothing. */
        findModuleByName: function () { return null; },
        findModuleByAddress: function () { return null; }
    };

    /* Memory.alloc — a bump allocator over a scratch region created lazily on the
     * first call, so the mtproto world (which never calls alloc) is byte-for-byte
     * unchanged. The boringssl engine needs it: pointerToScanPattern() allocs 8
     * bytes to render its Tier B needle as a scan pattern. The region is
     * enumerated:false so it is invisible to enumerateRanges()/maps and cannot
     * perturb range selection. */
    const SCRATCH_BASE = 0x7fff00000000n;
    const SCRATCH_SIZE = 0x10000;
    let scratchRegion = null;
    let scratchCursor = 0;
    function allocScratch(size) {
        if (scratchRegion === null) {
            scratchRegion = mem.add(new Region('scratch', SCRATCH_BASE, SCRATCH_SIZE,
                                               { enumerated: false }));
        }
        const address = SCRATCH_BASE + BigInt(scratchCursor);
        scratchCursor = align(scratchCursor + Number(size), 16);
        if (scratchCursor > SCRATCH_SIZE) throw new Error('scratch region exhausted');
        return new Ptr(mem, address);
    }

    const Memory = {
        alloc: function (size) { return allocScratch(size); },
        scanSync: function (base, size, pattern) {
            const tokens = String(pattern).trim().split(/\s+/);
            const needle = tokens.map((t) => (t === '??' || t === '?') ? null : parseInt(t, 16));
            const start = toBig(base);
            const region = mem.locate(start, size);
            if (region === null) throw new Error('invalid scan range at ' + base);
            const bytes = region.bytes;
            const offset = Number(start - region.base);
            const hits = [];
            for (let i = offset; i + needle.length <= offset + size; i++) {
                let matched = true;
                for (let j = 0; j < needle.length; j++) {
                    if (needle[j] !== null && bytes[i + j] !== needle[j]) { matched = false; break; }
                }
                if (matched) {
                    hits.push({ address: new Ptr(mem, region.base + BigInt(i)), size: needle.length });
                }
            }
            return hits;
        }
    };

    const File = {
        readAllText: function (p) {
            if (p === '/proc/self/maps') return mapsText;
            throw new Error('no such file: ' + p);
        }
    };

    /* The central oracle. Real SHA-1 by default — that is the whole point of the
     * round trip. `forcedDigests` exists for ONE case that no amount of synthetic
     * memory can produce honestly: emitKeylog()'s conflict rule fires when the
     * same id arrives carrying a different key, which in the field means a SHA-1
     * collision or a corrupted read. Stubbing the oracle to collide is the only
     * way to exercise that branch, and it is confined to scenarios that ask. */
    const Checksum = {
        compute: function (algorithm, buffer) {
            const u8 = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
            const forced = forcedDigests[hexOf(u8)];
            if (forced !== undefined) return forced;
            return nodeCrypto.createHash(algorithm).update(Buffer.from(u8)).digest('hex');
        }
    };

    const sandbox = {
        Process: Process,
        Memory: Memory,
        File: File,
        Checksum: Checksum,
        ptr: function (v) { return new Ptr(mem, toBig(v)); },
        send: function (message) { sent.push(message); },
        rpc: {},
        /* Anything the agent prints is diagnostics; stdout is reserved for the
         * one JSON line the pytest side parses. */
        console: {
            log: (...a) => process.stderr.write('[agent] ' + a.join(' ') + '\n'),
            warn: (...a) => process.stderr.write('[agent] ' + a.join(' ') + '\n'),
            error: (...a) => process.stderr.write('[agent] ' + a.join(' ') + '\n')
        }
    };
    if (clock !== null) sandbox.Date = { now: function () { return clock.now; } };
    return { sandbox: sandbox, sent: sent, mapsText: mapsText,
             exceptionHandlers: exceptionHandlers };
}

/* ---------------------------------------------------------------------------
 * Profile patching
 *
 * A scenario may need a profile that differs from the shipped one in a single
 * value — tiers.C_art_secretchat_key.rescan_every, say, which has to be
 * exercised as a number, as a nonsense value AND as an absent key. Patching the
 * parsed object is the only way to do that without a second copy of the JSON
 * drifting out of step with the real one.
 * ------------------------------------------------------------------------- */

function resolvePath(root, dotted) {
    const parts = dotted.split('.');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
        node = node[parts[i]];
        if (node === undefined || node === null) {
            throw new Error('no such profile path: ' + dotted);
        }
    }
    return [node, parts[parts.length - 1]];
}

function patchProfile(profile, scenario) {
    for (const dotted of (scenario.profile_delete || [])) {
        const [parent, key] = resolvePath(profile, dotted);
        delete parent[key];
    }
    const patch = scenario.profile_patch || {};
    for (const dotted of Object.keys(patch)) {
        const [parent, key] = resolvePath(profile, dotted);
        parent[key] = patch[dotted];
    }
    return profile;
}

/* ---------------------------------------------------------------------------
 * friTap-specific driver
 *
 * Build the COMPILED iife bundle, load it into the sandbox context so it sets
 * rpc.exports, run ONE scanOnce (Tier C runs on the first pass, so one is
 * enough), collect the keylog send() messages, and assert full key recovery.
 * ------------------------------------------------------------------------- */

/* Compile agent/memory_scan_agent.ts to a Node-runnable IIFE bundle. The default
 * esm format is NOT loadable by vm.runInContext (top-level import/export); -B iife
 * emits `(() => { ... rpc.exports = buildRpcExports(); })()`, which is. */
function compileIifeBundle() {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fritap-memscan-iife-'));
    const outFile = path.join(outDir, 'memory_scan_agent.iife.js');
    process.stderr.write('[harness] compiling ' + AGENT_ENTRY + ' -> ' + outFile + ' (-B iife)\n');
    execFileSync(FRIDA_COMPILE, [AGENT_ENTRY, '-o', outFile, '-B', 'iife'],
                 { cwd: PROJECT_ROOT, stdio: ['ignore', 'inherit', 'inherit'] });
    const source = fs.readFileSync(outFile, 'utf8');
    if (!/rpc\.exports\s*=/.test(source)) {
        throw new Error('compiled bundle does not assign rpc.exports; -B iife may have changed');
    }
    return { source, outFile };
}

/* The mtproto profile out of friTap's own database. */
function selectProfile(engine) {
    const database = JSON.parse(fs.readFileSync(PATTERNS_PATH, 'utf8'));
    const profiles = database.profiles || [];
    const profile = profiles.find((p) => p && p.engine === engine);
    if (profile === undefined) {
        throw new Error('no profile with engine=="' + engine + '" in ' + PATTERNS_PATH);
    }
    return profile;
}

/* Drive the compiled iife bundle once: create the vm context, run the bundle
 * (which assigns rpc.exports on the sandbox's `rpc` object), guard the exports,
 * configure() the profile, scanOnce(), and collect the emitted keylog lines. The
 * shared skeleton for every scenario; *tag* labels the diagnostics. Returns
 * {stats, keylogLines}. */
function driveBundle(source, outFile, profile, built, tag) {
    const context = vm.createContext(built.sandbox);
    vm.runInContext(source, context, { filename: outFile });
    const exports_ = built.sandbox.rpc.exports;
    if (!exports_ || typeof exports_.configure !== 'function' || typeof exports_.scanOnce !== 'function') {
        throw new Error('rpc.exports was not populated by the iife bundle (' + tag + ')');
    }

    const configured = exports_.configure(profile);
    process.stderr.write('[harness] (' + tag + ') configure() -> ' + JSON.stringify(configured) + '\n');
    if (!configured || configured.ok !== true) {
        throw new Error('(' + tag + ') configure() failed: ' + JSON.stringify(configured));
    }

    const stats = exports_.scanOnce();
    process.stderr.write('[harness] (' + tag + ') scanOnce() stats: ' + JSON.stringify(stats) + '\n');

    const keylogLines = new Set();
    for (const m of built.sent) {
        if (m && m.type === 'keylog' && typeof m.line === 'string') keylogLines.add(m.line);
    }
    return { stats, keylogLines };
}

/* The expected NSS-style keylog lines, reconstructed from the harness's own
 * `planted` record exactly as the agent's emitAuthKey()/emitE2eKey() build them:
 *   MTPROTO_AUTH_KEY <dcId> <keyId> <keyHex> <keyType>
 *   MTPROTO_E2E_KEY  <fingerprint> <keyHex> <chatId>
 * Reconstructing from `planted` (rather than trusting the agent's own line) is
 * what makes this an independent check of recovery. */
function expectedE2eKeyLine(chat) {
    return 'MTPROTO_E2E_KEY ' + chat.fingerprint + ' ' + chat.hex + ' ' + chat.chat_id;
}

/* ---------------------------------------------------------------------------
 * BoringSSL scenario
 *
 * A second, INDEPENDENT scenario that guards the boringssl engine (and, through
 * the shared cores it walks, the schannel/rc4 engines' scaffolding) against
 * regressions from the agent/ms_agent/ modular refactor — the mtproto scenario
 * exercises none of it.
 *
 * It synthesises the memory layout the boringssl profile expects for an IN-FLIGHT
 * TLS 1.3 handshake and asserts the engine recovers every labelled handshake
 * secret. The whole recovery pipeline is exercised end to end:
 *   Tier A  anchors on min_version||max_version (03 03 04 03) at hs+28, validates
 *           the seven stride-49 InplaceVector length bytes, closes the two-way
 *           pointer round trip hs->ssl->s3->hs, reads client_random from s3, and
 *           emits one keylog line per populated LABELLED slot; it also derives the
 *           Tier B needle from *(void**)ssl.
 *   Tier B  scans for that needle (ssl->method sits at offset 0), re-enters the
 *           very same handshakes through s3->hs and re-emits (deduped) the slots.
 *
 * Every offset, stride, anchor, length and NSS label comes from the profile — the
 * plant writes NOTHING the profile does not name — so this asserts the engine, not
 * a copy of its constants.
 * ------------------------------------------------------------------------- */

const BSSL_BASE = 0x7000000000n;   // realistic 39-bit userspace, above pointer_min
const BSSL_SIZE = 0x10000;

/* The boringssl profile out of friTap's own database (engine == "boringssl"). */
/* Build a single-region PartitionAlloc heap holding one SSL / SSL3_STATE /
 * SSL_HANDSHAKE trio wired into the hs->ssl->s3->hs round trip, with a distinct
 * secret in every labelled handshake slot. Returns a world buildSandbox() accepts
 * ({mem, planted, agentModule}) plus the expected client_random + secrets. */
function buildBoringsslWorld(profile) {
    const off = profile.struct_offsets;
    const c = profile.constants;
    const tierA = profile.tiers.A_ssl_handshake;

    /* One hash length used for every populated slot: readSlotLengths() rejects a
     * run whose non-zero length bytes disagree, so they must all match, and the
     * value has to be a member of constants.valid_hash_lens within the validator
     * length window. 48 (SHA-384) satisfies both. */
    const SECRET_LEN = c.valid_hash_lens[c.valid_hash_lens.length - 1];

    const mem = new Memspace();
    /* Anonymous (no file => require_anonymous keeps it) and named so
     * scan_regions.name_allowlist ["partition_alloc"] matches it. */
    mem.add(new Region('partition_alloc', BSSL_BASE, BSSL_SIZE, {
        mapsName: '[anon:partition_alloc]', fill: NATIVE_FILLER
    }));

    /* Four disjoint objects inside the one region. Offsets are arbitrary; only the
     * WIRING between them (taken from struct_offsets) is load-bearing. */
    const methodAddr = BSSL_BASE + 0x100n;   // static SSL_PROTOCOL_METHOD stand-in
    const sslAddr    = BSSL_BASE + 0x200n;
    const s3Addr     = BSSL_BASE + 0x400n;
    const hsAddr     = BSSL_BASE + 0x800n;

    function writeAt(address, bytes) { mem.write(address, bytes); }
    function writePointerAt(address, value) { new Ptr(mem, address).writePointer(value); }

    // --- SSL: method@0 (Tier B needle source) and s3@48 --------------------
    writePointerAt(sslAddr + BigInt(off.SSL.method), methodAddr);
    writePointerAt(sslAddr + BigInt(off.SSL.s3), s3Addr);

    // --- SSL3_STATE: client_random and the back-pointer to the handshake ----
    const clientRandom = makeSecretBytes('bssl-client-random', c.ssl3_random_size);
    writeAt(s3Addr + BigInt(off.SSL3_STATE.client_random), clientRandom);
    writePointerAt(s3Addr + BigInt(off.SSL3_STATE.hs), hsAddr);   // closes the round trip

    // --- SSL_HANDSHAKE: ssl back-pointer, version anchor, and the slot run --
    writePointerAt(hsAddr + BigInt(off.SSL_HANDSHAKE.ssl), sslAddr);
    writeAt(hsAddr + BigInt(off.SSL_HANDSHAKE.min_version), u16le(c.ssl_version_tls12)); // 03 03
    writeAt(hsAddr + BigInt(off.SSL_HANDSHAKE.max_version), u16le(c.ssl_version_tls13)); // 04 03

    /* Populate every LABELLED slot with a distinct secret at SECRET_LEN; leave the
     * two unlabelled slots (running secret + Finished MAC) at length 0 so
     * readSlotLengths() skips them and the run stays length-consistent. */
    const secrets = [];
    for (const slot of tierA.slots) {
        if (slot.label === null) {
            writeAt(hsAddr + BigInt(slot.len), Uint8Array.from([0]));
            continue;
        }
        const bytes = makeSecretBytes('bssl-' + slot.name, SECRET_LEN);
        writeAt(hsAddr + BigInt(slot.data), bytes);
        writeAt(hsAddr + BigInt(slot.len), Uint8Array.from([SECRET_LEN]));
        secrets.push({ label: slot.label, name: slot.name, hex: hexOf(bytes) });
    }

    const planted = {
        client_random: hexOf(clientRandom),
        secrets: secrets,
        partition_alloc_base: '0x' + BSSL_BASE.toString(16),
        ssl: '0x' + sslAddr.toString(16),
        s3: '0x' + s3Addr.toString(16),
        hs: '0x' + hsAddr.toString(16)
    };
    /* agentModule:false — no frida-overlaid range in this scenario. buildSandbox
     * reads only {mem, planted, agentModule}. */
    return { mem: mem, planted: planted, agentModule: false };
}

/* Run the boringssl scenario against the same compiled bundle. Returns true on
 * full recovery. Mirrors the mtproto runner: independent reconstruction of the
 * expected keylog lines from `planted`, so it checks the engine, not itself. */
function runBoringsslScenario(source, outFile) {
    const profile = selectProfile('boringssl');
    const world = buildBoringsslWorld(profile);
    const built = buildSandbox(world, profile, {}, null, undefined);

    const { keylogLines } = driveBundle(source, outFile, profile, built, 'boringssl');

    const cr = world.planted.client_random;
    /* Reconstruct the NSS-style line emitKeylog() builds: "<LABEL> <cr> <secret>". */
    const results = world.planted.secrets.map((s) => {
        const line = s.label + ' ' + cr + ' ' + s.hex;
        return { label: s.label, name: s.name, line: line, found: keylogLines.has(line) };
    });

    const out = process.stdout;
    out.write('\n=== friTap compiled boringssl agent — synthetic-heap TLS1.3 secret recovery ===\n');
    out.write('profile: ' + profile.id + '  (engine=' + profile.engine + ')\n');
    out.write('client_random: ' + cr + '\n');
    out.write('keylog lines emitted by agent: ' + keylogLines.size + '\n\n');
    out.write('-- planted TLS1.3 handshake secrets (' + results.length + ') --\n');
    for (const r of results) {
        out.write('  [' + (r.found ? 'OK ' : 'MISS') + '] ' + r.label + '  (' + r.name + ')\n');
    }

    const found = results.filter((r) => r.found).length;
    const pass = found === results.length && results.length > 0;
    out.write('\nboringssl secrets recovered: ' + found + '/' + results.length + '\n');

    if (!pass) {
        const misses = results.filter((r) => !r.found).map((r) => r.line);
        process.stderr.write('[harness] (boringssl) MISSING keylog lines:\n  ' + misses.join('\n  ') + '\n');
        process.stderr.write('[harness] (boringssl) recovered keylog lines were:\n  ' +
                             Array.from(keylogLines).join('\n  ') + '\n');
    }
    return pass;
}

/* Run the mtproto scenario against the compiled bundle. Returns true on full
 * key recovery. This is the former main() body, unchanged except that it takes
 * the already-compiled bundle and returns a boolean instead of setting
 * process.exitCode — the orchestrating main() combines it with the boringssl
 * scenario's result. */
function runMtprotoScenario(source, outFile) {
    /* readScenario()'s empty-scenario default: {} plants the default two
     * datacenter groups (dc 2 x3 slots, dc 4 x2 slots => 5 recoverable auth
     * keys) and one confirmed Secret-Chat key. */
    const scenario = {};

    const profile = patchProfile(selectProfile('mtproto'), scenario);

    const forcedDigests = {};
    const clock = buildClock(scenario);
    const world = buildWorld(scenario, profile);
    const built = buildSandbox(world, profile, forcedDigests, clock,
                               scenario.process_pointer_size);

    /* Tier C runs on the first pass (scanIndex 0 is never throttled), so the
     * single scanOnce inside driveBundle covers Tiers A/B (auth keys) AND Tier C
     * (secret-chat keys). */
    const { keylogLines } = driveBundle(source, outFile, profile, built, 'mtproto');

    const planted = world.planted;

    /* (a) every planted cloud auth key must appear as a MTPROTO_AUTH_KEY line. */
    const authResults = planted.auth_keys.map((k) => {
        const line = 'MTPROTO_AUTH_KEY ' + k.dc_id + ' ' + k.id + ' ' + k.hex + ' ' + k.key_type;
        return { name: k.name, dc_id: k.dc_id, id: k.id, role: k.role, line, found: keylogLines.has(line) };
    });

    /* (b) every planted (confirmed) secret-chat key must appear as a
     * MTPROTO_E2E_KEY line. */
    const e2eResults = planted.secret_chats
        .filter((c) => c.confirmed !== false)
        .map((c) => {
            const line = expectedE2eKeyLine(c);
            return { name: c.name, chat_id: c.chat_id, fingerprint: c.fingerprint, line, found: keylogLines.has(line) };
        });

    /* ------- report ------- */
    const out = process.stdout;
    out.write('\n=== friTap compiled mtproto agent — synthetic-heap key recovery ===\n');
    out.write('profile: ' + profile.id + '  (engine=' + profile.engine + ')\n');
    out.write('bundle : ' + outFile + '\n');
    out.write('keylog lines emitted by agent: ' + keylogLines.size + '\n\n');

    out.write('-- planted cloud auth keys (' + authResults.length + ') --\n');
    for (const r of authResults) {
        out.write('  [' + (r.found ? 'OK ' : 'MISS') + '] dc=' + r.dc_id + ' role=' + r.role +
                  ' id=' + r.id + '  (' + r.name + ')\n');
    }
    out.write('\n-- planted secret-chat (E2E) keys (' + e2eResults.length + ') --\n');
    for (const r of e2eResults) {
        out.write('  [' + (r.found ? 'OK ' : 'MISS') + '] chat_id=' + r.chat_id +
                  ' fingerprint=' + r.fingerprint + '  (' + r.name + ')\n');
    }

    const authFound = authResults.filter((r) => r.found).length;
    const e2eFound = e2eResults.filter((r) => r.found).length;
    const authOk = authFound === authResults.length && authResults.length > 0;
    const e2eOk = e2eFound === e2eResults.length && e2eResults.length > 0;
    const pass = authOk && e2eOk;

    out.write('\n=== SUMMARY ===\n');
    out.write('auth keys recovered: ' + authFound + '/' + authResults.length + '\n');
    out.write('E2E  keys recovered: ' + e2eFound + '/' + e2eResults.length + '\n');

    if (!pass) {
        const misses = [];
        for (const r of authResults) if (!r.found) misses.push('AUTH ' + r.line);
        for (const r of e2eResults) if (!r.found) misses.push('E2E  ' + r.line);
        out.write('\nmtproto scenario: FAIL\n');
        process.stderr.write('[harness] MISSING keylog lines:\n  ' + misses.join('\n  ') + '\n');
        process.stderr.write('[harness] recovered keylog lines were:\n  ' +
                             Array.from(keylogLines).join('\n  ') + '\n');
        return false;
    }

    out.write('\nmtproto scenario: PASS\n');
    return true;
}

/* Compile the agent bundle ONCE, then run every scenario against it. The process
 * exits non-zero if ANY scenario fails, so a boringssl regression fails the suite
 * exactly as an mtproto regression does. */
function main() {
    const { source, outFile } = compileIifeBundle();

    const mtprotoPass = runMtprotoScenario(source, outFile);
    const boringsslPass = runBoringsslScenario(source, outFile);

    const out = process.stdout;
    out.write('\n=== OVERALL ===\n');
    out.write('mtproto scenario:   ' + (mtprotoPass ? 'PASS' : 'FAIL') + '\n');
    out.write('boringssl scenario: ' + (boringsslPass ? 'PASS' : 'FAIL') + '\n');

    if (mtprotoPass && boringsslPass) {
        out.write('\nRESULT: PASS\n');
        process.exitCode = 0;
    } else {
        out.write('\nRESULT: FAIL\n');
        process.exitCode = 1;
    }
}

main();
