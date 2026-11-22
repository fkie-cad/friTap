// agent/shared/nss_keylog_locator.ts
//
// TIER 1 of NSS key extraction: locate NSS's own keylog writer and hook it
// read-only. The writer is the function that hex-encodes
// ss->ssl3.hs.client_random and writes one SSLKEYLOGFILE line:
// ssl3_WriteKeyLog(ss, label, const SECItem *secret) since NSS 3.115,
// ssl3_RecordKeyLog(ss, label, PK11SymKey *secret) before. It is neither
// exported nor out-of-line in every build, so it is found at runtime:
//
//   1. load sites of the labels passed DIRECTLY to the writer (CLIENT_RANDOM,
//      ECH_SECRET, ECH_CONFIG) -> the first call after each (backend);
//   2. candidates = those callees plus their direct callees (depth 1, covers a
//      non-LTO ssl3_RecordKeyLog that calls the writer);
//   3. exactly ONE candidate whose body decodes (hex table + one `ss + imm`)
//      is the writer, and the immediate is the client_random offset. Zero or
//      several -> miss (fail closed; tiers 2/3 take over).
//
// The seven TLS 1.3 labels reach the writer through tls13_DeriveSecretWrap, so
// they never vote; they only feed a logged diagnostic. Only this file is
// arch-neutral: label-site resolution and body decoding live in one backend per
// ABI (NssLocatorBackend). The hook only READS target memory.
//
// Deliberately does NOT import boringssl_anchor_locator.ts (its import
// registers BoringSSL tier 4 as a side effect).

import { log, devlog, devlog_debug } from "../util/log.js";
import { toHexString } from "../util/hex.js";
import {
    boundedModuleReader, isReadable, readableByteCount, resetReadableCache, safeReadPointer, safeReadU32,
} from "../util/safe_memory.js";
import { sendKeylog } from "./shared_structures.js";
import { moduleOffsetLabel, XrefScanAborted, type ScanStatus } from "./arm64_xref.js";
import {
    hasLearnedMiss, learnedFunction, learnedMissName, missFingerprint, rejectLearnedFunction,
    reportLearned, reportLearnedMisses,
} from "./learned_module_cache.js";
import { memoizePerMapping } from "./module_mapping.js";
import { isElfImage } from "./elf_build_id.js";
import { FifoSet } from "./lru.js";
import { isDecoded, LabelSelfCheck, type Decoded } from "./keylog_guards.js";
import { arm64NssLocatorBackend } from "./nss_keylog_backend_arm64.js";
import { x64NssLocatorBackend } from "./nss_keylog_backend_x64.js";
import { armNssLocatorBackend } from "./nss_keylog_backend_arm.js";

// ---- labels -----------------------------------------------------------------

/** Labels NSS passes straight to the keylog writer: the only ones that vote. */
export const NSS_DIRECT_WRITER_LABELS = ["CLIENT_RANDOM", "ECH_SECRET", "ECH_CONFIG"] as const;
/** Labels that go through tls13_DeriveSecretWrap first (diagnostic only). */
export const NSS_TLS13_LABELS = [
    "CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EARLY_EXPORTER_SECRET", "EXPORTER_SECRET",
] as const;
export const NSS_KEYLOG_LABELS: readonly string[] = [...NSS_DIRECT_WRITER_LABELS, ...NSS_TLS13_LABELS];
const LONGEST_LABEL = Math.max(...NSS_KEYLOG_LABELS.map((l) => l.length));

export function isKnownLabel(label: string | null): boolean {
    return label !== null && NSS_KEYLOG_LABELS.includes(label);
}

// ---- learned cache ----------------------------------------------------------

export const LEARNED_NSS_KEYLOG_WRITER = "nss.keylog_writer";
export const LEARNED_NSS_KEYLOG_WRITER_MISS = learnedMissName(LEARNED_NSS_KEYLOG_WRITER);
/** Bump the revision when the selection rule changes, so old miss markers go stale. */
export const NSS_KEYLOG_WRITER_MISS_FINGERPRINT = missFingerprint([...NSS_KEYLOG_LABELS, "revision", "1"]);

// ---- backend interface ------------------------------------------------------

export interface NssWriterDecode { clientRandomOff: number; }

/** The two arch-specific steps of the locator, one implementation per ABI. */
export interface NssLocatorBackend {
    /** Backend name for the per-run log line. */
    readonly name: string;
    /** True only for an ABI that has run on a device. */
    readonly deviceVerified: boolean;
    /**
     * Per label (index-aligned): the first direct-call target after each of its
     * load sites, all sites. Must follow a tail `b`/`jmp` to its target.
     */
    labelCallees(mod: Module, labels: string[], status: ScanStatus): Promise<NativePointer[][]>;
    /** Direct callees of `fn` that start a real function in `mod`; PLT stubs without bounds are skipped. */
    directCallees(fn: NativePointer, mod: Module): NativePointer[];
    /**
     * null unless: hex-table reference + exactly one "ss + imm" address computation;
     * DECODE_UNREADABLE when the body could not be read in full (no verdict). Accepts hookAddress(fn) too.
     */
    decodeWriter(fn: NativePointer, mod: Module): Decoded<NssWriterDecode>;
    /** Address to hook and to cache (sets the Thumb bit on arm32). */
    hookAddress(fn: NativePointer): NativePointer;
}

const BACKENDS: ReadonlyMap<string, NssLocatorBackend> = new Map([
    ["arm64", arm64NssLocatorBackend],
    // Static-only validation (Fenix 160.0.1 bytes); deviceVerified=false, logged as untested-abi.
    ["x64", x64NssLocatorBackend],
    ["arm", armNssLocatorBackend],
]);

/** The backend for `arch` (a Process.arch value), or null: an uncovered arch is a miss. */
export function nssLocatorBackendFor(arch: string): NssLocatorBackend | null {
    return BACKENDS.get(arch) ?? null;
}

// ---- pure selection helpers -------------------------------------------------

export interface PickedWriter<T, D> { candidate: T; decoded: D; }

/**
 * The single candidate whose body decodes, or null when none or more than one
 * (distinct by `keyOf`) does: an ambiguous build must fall back, never guess.
 */
export function pickKeylogWriter<T, D>(candidates: T[], decode: (c: T) => D | null,
                                       keyOf: (c: T) => string = String): PickedWriter<T, D> | null {
    const seen = new Set<string>();
    let picked: PickedWriter<T, D> | null = null;
    for (const candidate of candidates) {
        const key = keyOf(candidate);
        if (seen.has(key)) continue;
        seen.add(key);
        const decoded = decode(candidate);
        if (decoded === null) continue;
        if (picked !== null) return null;
        picked = { candidate, decoded };
    }
    return picked;
}

/** Largest secret a SECItem may carry here (TLS secrets are 32/48 bytes; ECH configs are larger). */
export const SECITEM_MAX_LEN = 512;

/** A pointer-sized `data` at +ptr that is readable for `len`, and `len` (u32 at +2*ptr) in 1..SECITEM_MAX_LEN. */
export function isSecItemShape(dataReadable: boolean, len: number | null): boolean {
    return dataReadable && len !== null && len >= 1 && len <= SECITEM_MAX_LEN;
}

export interface NssVersion { major: number; minor: number; }

/** "3.132" / "3.90.1 Basic ECC" -> { major: 3, minor: 132 }; null when unparseable. */
export function parseNssVersion(text: string | null): NssVersion | null {
    const match = text === null ? null : /^(\d+)\.(\d+)/.exec(text.trim());
    return match === null ? null : { major: Number(match[1]), minor: Number(match[2]) };
}

/** NSS 3.115 split ssl3_WriteKeyLog(ss, label, SECItem*) out of ssl3_RecordKeyLog(ss, label, PK11SymKey*). */
export function writerTakesSecItem(version: NssVersion): boolean {
    return version.major > 3 || (version.major === 3 && version.minor >= 115);
}

export type SecretSource = "secitem" | "symkey";

/**
 * How to read the writer's third argument, or null (drop the line) when the
 * shape probe disagrees with the version. An unknown version trusts only the
 * SECItem shape: calling into PK11 on a guess is not worth a key.
 */
export function secretSourceFor(version: NssVersion | null, secItemShaped: boolean): SecretSource | null {
    if (version === null) return secItemShaped ? "secitem" : null;
    if (writerTakesSecItem(version)) return secItemShaped ? "secitem" : null;
    return secItemShaped ? null : "symkey";
}

// ---- locate -----------------------------------------------------------------

export interface NssKeylogWriter {
    /** Hook address (backend.hookAddress of the decoded function). */
    writer: NativePointer;
    clientRandomOff: number;
    backend: NssLocatorBackend;
}

const writerByMapping = new Map<string, Promise<NssKeylogWriter | null>>();
let lastClientRandomOff: number | null = null;

/** client_random offset in sslSocket decoded from the last located writer, or null before any. */
export function nssClientRandomOffset(): number | null {
    return lastClientRandomOff;
}

/** "backend arm64, device-verified" / "backend none for mips" for the per-run log lines. */
function backendLabel(backend: NssLocatorBackend | null): string {
    if (backend === null) return `backend none for ${Process.arch}`;
    return `backend ${backend.name}, ${backend.deviceVerified ? "device-verified" : "untested-abi"}`;
}

function located(mod: Module, backend: NssLocatorBackend, writer: NativePointer, decoded: NssWriterDecode,
                 source: string): NssKeylogWriter {
    lastClientRandomOff = decoded.clientRandomOff;
    log(`[*] ${mod.name}: NSS keylog writer ${moduleOffsetLabel(mod, writer)} client_random +0x` +
        `${decoded.clientRandomOff.toString(16)} (${backendLabel(backend)}, ${source})`);
    return { writer, clientRandomOff: decoded.clientRandomOff, backend };
}

function missed(mod: Module, backend: NssLocatorBackend | null, why: string): null {
    log(`[-] ${mod.name}: NSS keylog writer not located (${backendLabel(backend)}): ${why}`);
    return null;
}

/** `pointers` without repeats, first occurrence order. */
function uniquePointers(pointers: NativePointer[]): NativePointer[] {
    return pointers.filter((p, i) => pointers.findIndex((q) => q.equals(p)) === i);
}

export type LearnedWriterVerdict<P, D> =
    | { kind: "hit"; cached: P; decoded: D }
    | { kind: "stale" }
    | { kind: "unreadable" }
    | { kind: "none" };

/**
 * Pure verdict on a learned-cache entry: one that decodes is a hit; one read in
 * full that no longer decodes is "stale" (the caller drops it); one that could
 * not be read proves nothing ("unreadable": the entry is kept, the caller scans).
 */
export function learnedWriterVerdict<P, D>(cached: P | null, decode: (p: P) => Decoded<D>): LearnedWriterVerdict<P, D> {
    if (cached === null) return { kind: "none" };
    const decoded = decode(cached);
    if (isDecoded(decoded)) return { kind: "hit", cached, decoded };
    return decoded === null ? { kind: "stale" } : { kind: "unreadable" };
}

/** The learned writer of `mod` while it still decodes; a stale entry is dropped, an unreadable one kept. */
function learnedWriter(mod: Module, backend: NssLocatorBackend): { fn: NativePointer; decoded: NssWriterDecode } | null {
    const cached = learnedFunction(mod, LEARNED_NSS_KEYLOG_WRITER);
    const verdict = learnedWriterVerdict(cached, (p) => backend.decodeWriter(p, mod));
    if (verdict.kind === "hit") return { fn: verdict.cached, decoded: verdict.decoded };
    if (verdict.kind === "stale") {
        rejectLearnedFunction(mod, LEARNED_NSS_KEYLOG_WRITER);
        devlog(`[nss-keylog] ${mod.name}: learned writer @ ${cached} no longer decodes; scanning`);
    } else if (verdict.kind === "unreadable") {
        devlog(`[nss-keylog] ${mod.name}: learned writer @ ${cached} could not be read; scanning instead`);
    }
    return null;
}

/** First-call targets of every label site, grouped by label; an aborted scan marks `status` incomplete. */
async function scanLabelCallees(mod: Module, backend: NssLocatorBackend, status: ScanStatus): Promise<NativePointer[][]> {
    try {
        return await backend.labelCallees(mod, [...NSS_KEYLOG_LABELS], status);
    } catch (e) {
        status.complete = false;
        if (!(e instanceof XrefScanAborted)) devlog(`[nss-keylog] ${mod.name}: label scan failed: ${e}`);
        return NSS_KEYLOG_LABELS.map(() => []);
    }
}

/** Direct-label callees plus their depth-1 callees, deduplicated. */
function writerCandidates(mod: Module, backend: NssLocatorBackend, callees: NativePointer[][]): NativePointer[] {
    const direct = callees.slice(0, NSS_DIRECT_WRITER_LABELS.length).flat();
    const all = [...direct];
    for (const fn of direct) {
        try { all.push(...backend.directCallees(fn, mod)); } catch (_e) { /* unreadable callee: skipped */ }
    }
    return uniquePointers(all);
}

/** Diagnostic only: does the TLS 1.3 labels' callee (tls13_DeriveSecretWrap) call the writer? */
function logTls13Diagnostic(mod: Module, backend: NssLocatorBackend, callees: NativePointer[][],
                            writer: NativePointer): void {
    const unique = uniquePointers(callees.slice(NSS_DIRECT_WRITER_LABELS.length).flat());
    const confirming = unique.filter((w) => {
        try { return backend.directCallees(w, mod).some((c) => backend.hookAddress(c).equals(writer)); } catch (_e) { return false; }
    });
    devlog(`[nss-keylog] ${mod.name}: TLS 1.3 label callees ${unique.map((p) => moduleOffsetLabel(mod, p)).join(",") || "none"}; ` +
        `${confirming.length} call the writer (diagnostic)`);
}

async function locateNssKeylogWriter(mod: Module): Promise<NssKeylogWriter | null> {
    // Tier 1 covers ELF only; Mach-O / PE modules go straight to the tier 2/3 fallback.
    if (!isElfImage(boundedModuleReader(mod))) return missed(mod, null, "not an ELF module (tier 1 covers ELF only)");
    const backend = nssLocatorBackendFor(Process.arch);
    if (backend === null) return missed(mod, null, "no locator backend for this architecture");
    const learned = learnedWriter(mod, backend);
    if (learned !== null) return located(mod, backend, learned.fn, learned.decoded, "learned cache");
    if (hasLearnedMiss(mod, LEARNED_NSS_KEYLOG_WRITER_MISS, NSS_KEYLOG_WRITER_MISS_FINGERPRINT)) {
        return missed(mod, backend, "learned cache records no writer in this build");
    }
    const status: ScanStatus = { complete: true };
    const callees = await scanLabelCallees(mod, backend, status);
    const candidates = writerCandidates(mod, backend, callees);
    const picked = pickKeylogWriter(candidates, (fn) => {
        try {
            const decoded = backend.decodeWriter(fn, mod);
            return isDecoded(decoded) ? decoded : null;
        } catch (_e) { return null; }
    }, (p) => p.toString());
    if (picked === null) {
        reportLearnedMisses(mod, { [LEARNED_NSS_KEYLOG_WRITER_MISS]: NSS_KEYLOG_WRITER_MISS_FINGERPRINT }, status);
        return missed(mod, backend, `${candidates.length} candidate(s), none or several decode`);
    }
    const writer = backend.hookAddress(picked.candidate);
    reportLearned(mod, { functions: { [LEARNED_NSS_KEYLOG_WRITER]: writer } });
    logTls13Diagnostic(mod, backend, callees, writer);
    return located(mod, backend, writer, picked.decoded, "scan");
}

/** Memoized writer lookup (learned cache, else scan): at most one scan per loaded mapping. */
function locateNssKeylogWriterCached(mod: Module): Promise<NssKeylogWriter | null> {
    return memoizePerMapping(writerByMapping, mod, () => locateNssKeylogWriter(mod));
}

// ---- hook -------------------------------------------------------------------

/** Consecutive calls with an unknown label before the hook is judged wrong and removed. */
export const LABEL_MISMATCH_LIMIT = 4;
const CLIENT_RANDOM_LEN = 32;
const SEC_SUCCESS = 0;
const MAX_DEDUPE_LINES = 4096;
/** Bytes read for a label: the longest known label plus its NUL. */
const LABEL_READ_BYTES = LONGEST_LABEL + 1;

export interface NssKeylogHookDeps {
    /** NSS version string ("3.132"); default: NSSSSL_GetVersion / NSS_GetVersion from the module's exports. */
    nssVersion?: () => string | null;
    /** Module-scoped export lookup (default: `mod`, then any loaded libnss3*). Never a global dlsym. */
    findExport?: (name: string) => NativePointer | null;
}

function loadedNss3Modules(): Module[] {
    try {
        return Process.enumerateModules().filter((m) => m.name.startsWith("libnss3"));
    } catch (_e) {
        return [];
    }
}

function defaultFindExport(mod: Module): (name: string) => NativePointer | null {
    return (name) => {
        for (const m of [mod, ...loadedNss3Modules()]) {
            try {
                const p = m.findExportByName(name);
                if (p !== null && !p.isNull()) return p;
            } catch (_e) { /* next module */ }
        }
        return null;
    };
}

function defaultNssVersion(findExport: (name: string) => NativePointer | null): () => string | null {
    return () => {
        for (const name of ["NSSSSL_GetVersion", "NSS_GetVersion"]) {
            const fn = findExport(name);
            if (fn === null) continue;
            try {
                const text = (new NativeFunction(fn, "pointer", []) as () => NativePointer)();
                if (!text.isNull()) return text.readCString();
            } catch (_e) { /* try the next export */ }
        }
        return null;
    };
}

/** NUL-terminated label at `p` (one range check, one read); null when unreadable or too long. */
function readLabel(p: NativePointer): string | null {
    const readable = readableByteCount(p, LABEL_READ_BYTES);
    if (readable === 0) return null;
    let bytes: Uint8Array;
    try { bytes = new Uint8Array(p.readByteArray(readable)!); } catch (_e) { return null; }
    const nul = bytes.indexOf(0);
    return nul < 0 ? null : String.fromCharCode(...bytes.subarray(0, nul));
}

/** Bytes of a SECItem* when it has the SECItem shape, else null. */
function readSecItem(item: NativePointer): ArrayBuffer | null {
    if (item.isNull()) return null;
    const data = safeReadPointer(item.add(Process.pointerSize));
    const len = safeReadU32(item.add(2 * Process.pointerSize));
    const dataReadable = data !== null && !data.isNull() && len !== null && isReadable(data, len);
    if (!isSecItemShape(dataReadable, len)) return null;
    try { return data!.readByteArray(len!); } catch (_e) { return null; }
}

function isAllZero(bytes: ArrayBuffer): boolean {
    return new Uint8Array(bytes).every((b) => b === 0);
}

interface Pk11KeyFunctions { extract: (k: NativePointer) => number; getData: (k: NativePointer) => NativePointer; }

/** Per-hook state: version, lazily bound PK11 functions, self-check counter, dedupe set. */
class NssKeylogHookState {
    readonly labelCheck = new LabelSelfCheck(isKnownLabel, LABEL_MISMATCH_LIMIT);
    readonly lines = new FifoSet<string>(MAX_DEDUPE_LINES);
    /** undefined: not looked up yet; null: the exports are missing (remembered, not re-enumerated per call). */
    private pk11: Pk11KeyFunctions | null | undefined = undefined;

    constructor(readonly mod: Module, readonly writer: NssKeylogWriter, readonly version: NssVersion | null,
                private readonly findExport: (name: string) => NativePointer | null) {}

    /** PK11_ExtractKeyValue + PK11_GetKeyData, what pre-3.115 ssl3_RecordKeyLog itself calls. */
    readSymKey(key: NativePointer): ArrayBuffer | null {
        if (this.pk11 === undefined) this.pk11 = this.bindPk11();
        if (this.pk11 === null || this.pk11.extract(key) !== SEC_SUCCESS) return null;
        return readSecItem(this.pk11.getData(key));
    }

    private bindPk11(): Pk11KeyFunctions | null {
        const extract = this.findExport("PK11_ExtractKeyValue");
        const getData = this.findExport("PK11_GetKeyData");
        if (extract === null || getData === null) return null;
        return {
            extract: new NativeFunction(extract, "int", ["pointer"]) as (k: NativePointer) => number,
            getData: new NativeFunction(getData, "pointer", ["pointer"]) as (k: NativePointer) => NativePointer,
        };
    }

    emit(line: string): void {
        if (this.lines.has(line)) return;
        this.lines.add(line);
        sendKeylog(line, null, this.mod.name);
    }
}

function readSecret(state: NssKeylogHookState, arg: NativePointer): ArrayBuffer | null {
    const asSecItem = readSecItem(arg);
    const source = secretSourceFor(state.version, asSecItem !== null);
    if (source === "secitem") return asSecItem;
    if (source === "symkey") return state.readSymKey(arg);
    return null;
}

function readClientRandom(ss: NativePointer, offset: number): ArrayBuffer | null {
    const at = ss.add(offset);
    if (!isReadable(at, CLIENT_RANDOM_LEN)) return null;
    try { return at.readByteArray(CLIENT_RANDOM_LEN); } catch (_e) { return null; }
}

/** One writer call: label self-check, then the line NSS itself would log. Returns false to detach. */
function onWriterCall(state: NssKeylogHookState, ss: NativePointer, labelPtr: NativePointer,
                      secretArg: NativePointer): boolean {
    resetReadableCache();
    const label = readLabel(labelPtr);
    const verdict = state.labelCheck.observe(label);
    if (verdict !== "emit") return verdict === "skip";
    const secret = readSecret(state, secretArg);
    const clientRandom = readClientRandom(ss, state.writer.clientRandomOff);
    if (secret === null || clientRandom === null || isAllZero(clientRandom)) return true;
    state.emit(`${label} ${toHexString(clientRandom)} ${toHexString(secret)}`);
    return true;
}

const installedByMapping = new Map<string, Promise<boolean>>();

function attachWriterHook(mod: Module, writer: NssKeylogWriter, deps: NssKeylogHookDeps): boolean {
    const findExport = deps.findExport ?? defaultFindExport(mod);
    const versionText = (deps.nssVersion ?? defaultNssVersion(findExport))();
    const state = new NssKeylogHookState(mod, writer, parseNssVersion(versionText), findExport);
    let listener: InvocationListener | null = null;
    try {
        listener = Interceptor.attach(writer.writer, {
            onEnter(args) {
                try {
                    if (onWriterCall(state, args[0], args[1], args[2]) || listener === null) return;
                    listener.detach();
                    listener = null;
                    rejectLearnedFunction(mod, LEARNED_NSS_KEYLOG_WRITER);
                    log(`[-] ${mod.name}: NSS keylog writer hook saw ${LABEL_MISMATCH_LIMIT} unknown labels in a row; removed`);
                } catch (e) {
                    devlog(`[nss-keylog] ${mod.name}: writer hook error: ${e}`);
                }
            },
        });
    } catch (e) {
        log(`[-] ${mod.name}: could not hook the NSS keylog writer at ${writer.writer}: ${e}`);
        return false;
    }
    devlog_debug(`[nss-keylog] ${mod.name}: writer hook installed (NSS ${versionText ?? "version unknown"})`);
    return true;
}

/**
 * Locate the keylog writer of `mod` and hook it (read-only). Resolves true iff
 * a hook is installed; tiers 2/3 should run only after this settles false.
 */
export function installNssKeylogHook(mod: Module, deps: NssKeylogHookDeps = {}): Promise<boolean> {
    return memoizePerMapping(installedByMapping, mod, async () => {
        const writer = await locateNssKeylogWriterCached(mod);
        return writer !== null && attachWriterHook(mod, writer, deps);
    });
}
