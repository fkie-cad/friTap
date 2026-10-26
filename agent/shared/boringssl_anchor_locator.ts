// agent/shared/boringssl_anchor_locator.ts
//
// TIER 4 — the last-resort BoringSSL keylog installer for FULLY STRIPPED Android
// binaries (e.g. Chrome's libchrome.so, libhttpengine.so) where every earlier
// tier has missed: no SSL_CTX_set_keylog_callback export (tier 1), no
// ssl_log_secret symbol (tier 2), and no byte pattern matched (tier 3). It runs
// from onAllKeylogTiersMissed() (boringssl_keylog_outcome.ts), which registers
// this module as its tier-4 runner — or, in the legacy Cronet chain, right after
// the symbol tier missed, in parallel with a still-running pattern scan
// (startTier4InParallelWithPattern). Either way at most once per module.
//
// HOW IT FINDS ssl_log_secret WITHOUT SYMBOLS OR PATTERNS
//   BoringSSL logs each secret by calling ssl_log_secret(ssl, LABEL, secret),
//   where LABEL is one of a small set of NSS keylog label strings baked into the
//   binary ("CLIENT_RANDOM", "*_TRAFFIC_SECRET*", "EXPORTER_SECRET", ...). So:
//     (a) locate each NUL-terminated label string in the module's rodata;
//     (b) find the code sites that materialise each string's address — ONE
//         native Memory.scanSync pass for all labels, chunked so it yields to
//         the event loop (a per-word JS walk took ~10 min per label on
//         libchrome.so and blocked the agent; see arm64_xref.ts);
//     (c) from each site, take the next direct call — that call IS ssl_log_secret;
//     (d) accept the callee only if >= 2 different labels agree on it, else reject.
//   The string-walk/xref primitives are the shared arm64_xref helpers (also used
//   by the Signal libsignal discovery); arm64.ts supplies the pure decoders.
//
// HOW IT PRODUCES KEY LINES (with as few ABI assumptions as possible)
//   PREFERRED — decode the ctx offsets out of ssl_log_secret's own prologue.
//   Its first instructions load ssl->ctx then ctx->keylog_callback before an
//   early-return null-check branch, e.g.
//       ldr x8, [x0, #0x68]     ; x8 = ssl->ctx
//       ldr x8, [x8, #0x250]    ; x8 = ctx->keylog_callback
//       cbz/cbnz x8, ...        ; return early if not set
//   decodeCtxKeylogOffsets() decodes those two immediates generically (register
//   flow x0 -> xN -> xM, then the null-check on xM), following the model of
//   deriveOffsetFromBinary() in apple_keylog_offset.ts. In onEnter we install
//   friTap's own NativeCallback into that field only when it is NULL and writable
//   (the three guards from installKeylogCallbackViaCtxWrite). BoringSSL then
//   formats the NSS line itself, so no s3/client_random offsets are needed.
//
//   FALLBACK — if the offsets do not decode, hook ssl_log_secret directly with
//   the chain's dumpKeys callback (the boringSslDumpKeys s3-struct-walk style).
//
// arm64 only; other architectures are logged once and skipped. --pairip-safe
// disables this tier (it is a memory scan) — that gate lives in the caller
// (onAllKeylogTiersMissed), which does not run tier 4 when the pattern tier was
// disabled for pairip.

import { log, devlog, _isShuttingDownNow } from "../util/log.js";
import { sendKeylog } from "./shared_structures.js";
import {
    isLDRimmU64, isCBZ64, isCBNZ64, decodeLDRU64Imm, regRd, regRn,
} from "./arm64.js";
import {
    findAnchorStringsAsync, findStringLoadSitesAsync, firstCallTargetForward,
} from "./arm64_xref.js";
import { isReadable, isWritable, safeReadPointer, resetReadableCache } from "../util/safe_memory.js";
import { claimKeylogHook, keylogHookOwner, registerBoringSSLTier4 } from "./boringssl_keylog_outcome.js";
import type { DumpKeysCb } from "./boringssl_symbol_hook.js";
import { argAt, callAbiForModule, readSslLogSecretCall, type CallAbi } from "./call_abi.js";
import { scanRangesChunked, yieldToEventLoop, XREF_SCAN_CHUNK_BYTES, type ScanRange } from "./arm64_xref.js";
import {
    CALL_SEARCH_WINDOW, decodeX64CtxKeylogOffsets, findRipLeaRefs, firstCallAfter, LEA_ARG1_PREFIX, X64_REG,
} from "./x64_xref.js";
import { findModuleOrPeImage, type ModuleLike } from "../util/proc_maps.js";
import { toHexPattern } from "../util/hex.js";
import { makeWin64ToSysvThunk } from "./win64_thunk.js";
import { offsets } from "../fritap_agent.js";

/**
 * BoringSSL's NSS keylog label strings. ssl_log_secret is called once per label
 * during a handshake, so each is a separate xref anchor into the same callee.
 */
export const BORINGSSL_KEYLOG_LABELS: string[] = [
    "CLIENT_RANDOM",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

// A ctx field offset must be plausible: a struct member displacement, not a
// nonsense immediate. Looser than apple_keylog_offset.ts's 0x80 floor because
// ssl->ctx sits early in SSL (observed 0x68), while keylog_callback sits deep in
// SSL_CTX (observed 0x250).
const MIN_CTX_FIELD_OFFSET = 0x8;
const MAX_CTX_FIELD_OFFSET = 0x4000;

// Instructions of ssl_log_secret's prologue to inspect for the two loads.
const PROLOGUE_WORDS = 12;

/**
 * Decode ssl->ctx and ctx->keylog_callback offsets from ssl_log_secret's leading
 * instruction words. Pure (numbers only), so it is unit-testable without Frida.
 *
 * Shape required (register flow x0 -> xN -> xM, then a null-check on xM):
 *     ldr xN, [x0,  #ctxOff]     ; N != 0  (x0 is the ssl argument)
 *     ldr xM, [xN,  #cbOff]
 *     cbz/cbnz xM, <early-return>
 *
 * Returns null unless all three are present with plausible offsets — a wrong
 * answer here would write a function pointer into the wrong struct field and
 * crash the target, exactly as on Apple (fkie-cad/friTap#65).
 */
export function decodeCtxKeylogOffsets(
    words: number[],
): { ctxOff: number; cbOff: number } | null {
    // Step 1: the first LDR that reads from x0 -> xN (ssl->ctx).
    let ctxOff: number | null = null;
    let reg1 = -1;
    let i1 = -1;
    for (let i = 0; i < words.length; i++) {
        const w = words[i] >>> 0;
        if (isLDRimmU64(w) && regRn(w) === 0) {
            ctxOff = decodeLDRU64Imm(w);
            reg1 = regRd(w);
            i1 = i;
            break;
        }
    }
    if (ctxOff === null || reg1 === 0) return null; // reg1 == x0 would alias ssl
    if (ctxOff < MIN_CTX_FIELD_OFFSET || ctxOff > MAX_CTX_FIELD_OFFSET) return null;

    // Step 2: an LDR that reads from xN -> xM (ctx->keylog_callback).
    let cbOff: number | null = null;
    let reg2 = -1;
    let i2 = -1;
    for (let i = i1 + 1; i < words.length; i++) {
        const w = words[i] >>> 0;
        if (isLDRimmU64(w) && regRn(w) === reg1) {
            cbOff = decodeLDRU64Imm(w);
            reg2 = regRd(w);
            i2 = i;
            break;
        }
    }
    if (cbOff === null) return null;
    if (cbOff < MIN_CTX_FIELD_OFFSET || cbOff > MAX_CTX_FIELD_OFFSET) return null;

    // Step 3: the keylog_callback null-check branch on xM confirms the pair.
    for (let i = i2 + 1; i < words.length; i++) {
        const w = words[i] >>> 0;
        if ((isCBZ64(w) || isCBNZ64(w)) && regRd(w) === reg2) {
            return { ctxOff, cbOff };
        }
    }
    return null;
}

/**
 * The agreement rule: accept a callee only when at least 2 DIFFERENT labels
 * resolved to it. Pure (strings only), so it is unit-testable without Frida.
 * Returns the most-agreed callee, or null when none reaches 2 — or when two or
 * more callees tie for the most votes: there is then no evidence for either,
 * and a wrong callee is worse than none (fail closed).
 */
export function pickAgreedCallee(pairs: { label: string; callee: string }[]): string | null {
    // One vote per distinct label (guard against a label appearing twice).
    const perLabel = new Map<string, string>();
    for (const { label, callee } of pairs) {
        if (!perLabel.has(label)) perLabel.set(label, callee);
    }
    const votes = new Map<string, number>();
    for (const callee of perLabel.values()) {
        votes.set(callee, (votes.get(callee) ?? 0) + 1);
    }
    let best: string | null = null;
    let bestCount = 0;
    let tied = false;
    for (const [callee, count] of votes) {
        if (count > bestCount) {
            best = callee;
            bestCount = count;
            tied = false;
        } else if (count === bestCount) {
            tied = true;
        }
    }
    return bestCount >= 2 && !tied ? best : null;
}

// GC roots — a keylog NativeCallback handed to native code MUST be rooted for
// the lifetime of the process, or Frida frees it and BoringSSL calls a dangling
// pointer (see pairip_blink.ts's rootedCallbacks for the same requirement).
const rootedCallbacks: NativeCallback<any, any>[] = [];

// Every ctx->keylog_callback field the ctx-write path filled in, with the
// callback it holds. On detach they MUST be put back to NULL: the NativeCallback
// is freed with the script, and BoringSSL would call the dangling pointer on the
// next handshake (observed on Chrome: SIGSEGV in ssl_log_secret seconds after a
// clean detach). Keyed by field address.
const writtenKeylogFields = new Map<string, { field: NativePointer; cb: NativePointer }>();

/**
 * Detach-time cleanup (called from gracefulDetach AND from Frida's `dispose`
 * RPC hook on any script unload, after Interceptor.detachAll): NULL every
 * keylog_callback field we wrote that still holds our callback.
 * Returns how many were restored. Never throws. Idempotent: the bookkeeping is
 * cleared, so a second call (gracefulDetach followed by dispose) restores 0.
 */
export function restoreAnchorLocatorKeylogFields(): number {
    let restored = 0;
    for (const { field, cb } of writtenKeylogFields.values()) {
        try {
            if (!isWritable(field, Process.pointerSize)) continue;
            const current = safeReadPointer(field);
            if (current === null || !current.equals(cb)) continue; // ctx freed/reused or changed
            field.writePointer(NULL);
            restored++;
        } catch (_e) { /* best effort */ }
    }
    writtenKeylogFields.clear();
    return restored;
}

let loggedNonArm64 = false;

/**
 * Read up to PROLOGUE_WORDS instruction words at `addr` and decode the ctx
 * offsets. Range-checked because enumerateSymbols/xref can hand back addresses
 * that are not fully mapped, and a fault here is fatal.
 */
function deriveOffsetsAt(addr: NativePointer): { ctxOff: number; cbOff: number } | null {
    try {
        const words: number[] = [];
        for (let i = 0; i < PROLOGUE_WORDS; i++) {
            const at = addr.add(i * 4);
            if (!isReadable(at, 4)) return null;
            words.push(at.readU32());
        }
        return decodeCtxKeylogOffsets(words);
    } catch (e) {
        devlog(`[anchor-locator] prologue decode failed: ${e}`);
        return null;
    }
}

/**
 * PREFERRED path: attach ssl_log_secret and, on first entry, install friTap's
 * keylog NativeCallback into the (currently NULL) ctx->keylog_callback field.
 * BoringSSL then formats and emits every NSS line through that callback.
 */
function installViaCtxWrite(
    moduleName: string,
    fnAddr: NativePointer,
    offs: { ctxOff: number; cbOff: number },
    abi: CallAbi | null = null,
): boolean {
    const { ctxOff, cbOff } = offs;
    let dropLogged = false;
    const emitKeylogLine = (linePtr: NativePointer): void => {
        try {
            if (linePtr.isNull()) return;
            // This path emits through BoringSSL's keylog_callback, not through
            // the guarded dumpKeys, so apply the per-module ownership guard
            // here: tier 4 can run in parallel with a pattern scan, and a
            // pattern hook that delivered a secret first owns the module.
            if (!claimKeylogHook(moduleName, "anchor")) {
                if (!dropLogged) {
                    dropLogged = true;
                    devlog(`[anchor-locator] ${moduleName}: the ${keylogHookOwner(moduleName)} tier owns this module; dropping duplicate keylog lines`);
                }
                return;
            }
            const line = linePtr.readCString();
            if (line) sendKeylog(line);
        } catch (e) {
            devlog(`[anchor-locator] ${moduleName}: keylog callback error: ${e}`);
        }
    };
    const keylogCb = new NativeCallback(function (_ssl: NativePointer, linePtr: NativePointer) {
        emitKeylogLine(linePtr);
    }, "void", ["pointer", "pointer"]);
    rootedCallbacks.push(keylogCb); // load-bearing GC root
    // The pointer BoringSSL will call. Win64 code under Wine (Linux-host Frida,
    // which has no "win64" NativeCallback ABI) calls it through a thunk.
    const cbEntry: NativePointer = (abi === "win64" && Process.platform !== "windows")
        ? makeWin64ToSysvThunk(keylogCb, 2)
        : keylogCb;

    let installedOnce = false;
    let vetoedOnce = false;
    // App-owned keylog callbacks already hooked, by address.
    const hookedExisting = new Set<string>();
    const hookExistingKeylogCallback = (fn: NativePointer): void => {
        const key = fn.toString();
        if (hookedExisting.has(key)) return;
        hookedExisting.add(key);
        const range = Process.findRangeByAddress(fn);
        if (range === null || !range.protection.includes("x")) {
            log(`[-] ${moduleName}: ctx+0x${cbOff.toString(16)} holds ${fn}, which is not code; leaving it alone.`);
            return;
        }
        try {
            Interceptor.attach(fn, {
                onEnter(args: InvocationArguments) {
                    // keylog_callback(const SSL *ssl, const char *line)
                    emitKeylogLine(abi === null ? args[1] : argAt(this.context, abi, 1));
                },
            });
            log(`[*] ${moduleName}: the app already sets a keylog callback (${fn}); hooked it instead of replacing it`);
        } catch (e) {
            log(`[-] ${moduleName}: could not hook the app's keylog callback at ${fn}: ${e}`);
        }
    };
    try {
        Interceptor.attach(fnAddr, {
            onEnter(args: InvocationArguments) {
                try {
                    const ssl = abi === null ? args[0] : argAt(this.context, abi, 0);
                    if (ssl.isNull()) return;
                    const ctx = safeReadPointer(ssl.add(ctxOff));
                    if (ctx === null || ctx.isNull()) return;
                    const field = ctx.add(cbOff);
                    // Cheap cached read first: once installed, every later call
                    // returns here without the uncached isWritable range lookup.
                    const current = safeReadPointer(field);
                    if (current !== null && current.equals(cbEntry)) return; // ours already
                    if (!isWritable(field, Process.pointerSize)) {
                        if (!vetoedOnce) {
                            vetoedOnce = true;
                            log(`[-] ${moduleName}: anchor-locator refused the keylog write — ` +
                                `ctx+0x${cbOff.toString(16)} is not writable (offset likely wrong).`);
                        }
                        return;
                    }
                    if (current === null) return;
                    if (!current.isNull()) {
                        // The app registered its own keylog callback (e.g. Chromium
                        // with --ssl-key-log-file / SSLKEYLOGFILE). Never overwrite
                        // it; hook it instead — BoringSSL hands it the same line.
                        hookExistingKeylogCallback(current);
                        return;
                    }
                    if (_isShuttingDownNow()) return; // detach is restoring these fields
                    field.writePointer(cbEntry);
                    writtenKeylogFields.set(field.toString(), { field, cb: cbEntry });
                    if (!installedOnce) {
                        installedOnce = true;
                        devlog(`[anchor-locator] ${moduleName}: wrote keylog_callback at ctx+0x${cbOff.toString(16)}`);
                    }
                } catch (e) {
                    if (!vetoedOnce) {
                        vetoedOnce = true;
                        log(`[-] ${moduleName}: anchor-locator keylog install failed: ${e}`);
                    }
                }
            },
        });
    } catch (e) {
        devlog(`[anchor-locator] ${moduleName}: Interceptor.attach (ctx-write) failed: ${e}`);
        return false;
    }
    log(`[*] ${moduleName}: keylog hooks installed via anchor-locator ` +
        `(derived ctx offsets 0x${ctxOff.toString(16)}/0x${cbOff.toString(16)})`);
    return true;
}

/**
 * FALLBACK path: the offsets did not decode, so hook ssl_log_secret directly and
 * emit each secret through the chain's dumpKeys (the s3-struct-walk NSS style).
 */
function installViaFieldDump(
    moduleName: string,
    fnAddr: NativePointer,
    dumpKeys: DumpKeysCb,
    abi: CallAbi | null = null,
): boolean {
    try {
        Interceptor.attach(fnAddr, {
            onEnter(args: InvocationArguments) {
                // bssl::ssl_log_secret(SSL const*, char const*, Span<u8 const>);
                // the Span is passed by reference on Win64 (see call_abi.ts).
                const c = readSslLogSecretCall(args, this.context, abi);
                dumpKeys(c.label, c.ssl, c.data, c.len);
            },
        });
    } catch (e) {
        devlog(`[anchor-locator] ${moduleName}: Interceptor.attach (field dump) failed: ${e}`);
        return false;
    }
    log(`[*] ${moduleName}: keylog hooks installed via anchor-locator (field dump)`);
    return true;
}

/** A (label, callee) vote per label: the first load site that reaches a direct call. */
export function collectLabelVotes(
    labels: string[],
    sitesPerLabel: NativePointer[][],
    firstCallee: (site: NativePointer) => NativePointer | null,
): { label: string; callee: string }[] {
    const pairs: { label: string; callee: string }[] = [];
    labels.forEach((label, i) => {
        for (const site of sitesPerLabel[i] ?? []) {
            const callee = firstCallee(site);
            if (callee !== null) {
                pairs.push({ label, callee: callee.toString() });
                break;
            }
        }
    });
    return pairs;
}

/** Megabytes of executable code in `mod` (for the timing log). */
function codeMegabytes(mod: Module): string {
    let bytes = 0;
    for (const r of mod.enumerateRanges("r-x")) bytes += r.size;
    return (bytes / (1024 * 1024)).toFixed(1);
}

/**
 * (a)-(d): locate the labels, find every label's load sites in ONE native,
 * chunked pass (yielding to the event loop between chunks), resolve each
 * label's callee and apply the >=2-labels agreement rule.
 */
async function locateSslLogSecret(mod: Module, moduleName: string): Promise<NativePointer | null> {
    const modStart = mod.base;
    const modEnd = mod.base.add(mod.size);
    const started = Date.now();
    devlog(`[anchor-locator] ${moduleName}: scanning ${codeMegabytes(mod)} MB of code for ` +
        `${BORINGSSL_KEYLOG_LABELS.length} keylog label xrefs (background, non-blocking)`);

    const strAddrs = await findAnchorStringsAsync(mod, BORINGSSL_KEYLOG_LABELS.map((l) => l + "\u0000"));
    const labels: string[] = [];
    const targets: NativePointer[] = [];
    strAddrs.forEach((a, i) => { if (a !== null) { labels.push(BORINGSSL_KEYLOG_LABELS[i]); targets.push(a); } });

    const sites = targets.length > 0 ? await findStringLoadSitesAsync(mod, targets) : [];
    const pairs = collectLabelVotes(labels, sites,
        (site) => firstCallTargetForward(site, modEnd, modStart, modEnd));
    devlog(`[anchor-locator] ${moduleName}: xref scan finished in ${Date.now() - started} ms ` +
        `(${targets.length} label string(s), ${pairs.length} resolved a call)`);

    devlog(`[anchor-locator] ${moduleName}: votes ` +
        (pairs.map((p) => `${p.label}->${p.callee}`).join(", ") || "(none)"));

    const agreed = pickAgreedCallee(pairs);
    if (agreed === null) {
        devlog(`[anchor-locator] ${moduleName}: no ssl_log_secret candidate agreed across ` +
            `>=2 labels (${pairs.length} label(s) resolved a call)`);
        return null;
    }
    devlog(`[anchor-locator] ${moduleName}: ssl_log_secret candidate @ ${agreed} ` +
        `(agreed by ${pairs.filter((p) => p.callee === agreed).length}/${pairs.length} label xref(s))`);
    return ptr(agreed);
}

/**
 * Tier-4 entry point (registered with boringssl_keylog_outcome). Resolves true
 * iff a keylog hook was installed. ASYNC: the xref scan yields to the event loop
 * between chunks, so other hooks, messages and detach are served while it runs;
 * the caller reports the outcome when the promise settles. --pairip-safe gating
 * is the caller's job.
 */
export async function runAnchorLocatorTier4(
    moduleName: string,
    dumpKeys: DumpKeysCb,
    _detail?: string,
): Promise<boolean> {
    if (Process.arch === "x64") {
        const xmod = findModuleOrPeImage(moduleName);
        if (xmod === null) {
            devlog(`[anchor-locator] ${moduleName}: not loaded`);
            return false;
        }
        return runAnchorLocatorX64(xmod, dumpKeys, callAbiForModule(moduleName) ?? "sysv");
    }
    if (Process.arch !== "arm64") {
        if (!loggedNonArm64) {
            loggedNonArm64 = true;
            log(`[*] anchor-locator (tier 4) skipped: only implemented for arm64 and x64 (arch=${Process.arch})`);
        }
        return false;
    }

    let mod: Module | null;
    try {
        mod = Process.findModuleByName(moduleName);
    } catch (e) {
        devlog(`[anchor-locator] ${moduleName}: findModuleByName threw: ${e}`);
        return false;
    }
    if (mod === null) {
        devlog(`[anchor-locator] ${moduleName}: not loaded`);
        return false;
    }

    const sslLogSecret = await locateSslLogSecret(mod, moduleName);
    if (sslLogSecret === null) return false;
    // The scan above yields to the JS loop; a detach/dispose that ran meanwhile
    // has already restored the keylog fields, so installing now would leave a
    // hook (and possibly a ctx write) behind that nothing will ever undo.
    if (_isShuttingDownNow()) {
        devlog(`[anchor-locator] ${moduleName}: shutdown during ssl_log_secret scan; not installing`);
        return false;
    }

    resetReadableCache();
    const offs = deriveOffsetsAt(sslLogSecret);
    if (offs !== null) {
        return installViaCtxWrite(moduleName, sslLogSecret, offs);
    }
    devlog(`[anchor-locator] ${moduleName}: ctx-offset decode failed; using field-dump fallback`);
    return installViaFieldDump(moduleName, sslLogSecret, dumpKeys);
}

// ---- x86-64 (Windows PE / Wine PE / Linux ELF) ----------------------------

// Overlap so a LEA plus its call window that straddles a chunk boundary is
// still seen whole by the chunk the LEA starts in.
const X64_CHUNK_OVERLAP = 7 + CALL_SEARCH_WINDOW + 5;

/**
 * Address -> label of each keylog label string in `mod`'s data. The string must
 * be NUL-delimited on both sides (the preceding NUL keeps "EXPORTER_SECRET"
 * from matching the tail of a longer string).
 */
async function findLabelStringsX64(mod: Module | ModuleLike): Promise<Map<number, string>> {
    const found = new Map<number, string>();
    const have = new Set<string>();
    const data = mod.enumerateRanges("r--") as ScanRange[];
    await scanRangesChunked(data, BORINGSSL_KEYLOG_LABELS.map((label) => ({
        pattern: toHexPattern("\u0000" + label + "\u0000"),
        onMatch: (a: NativePointer) => {
            if (have.has(label)) return;
            have.add(label);
            found.set(Number(a.add(1).toString()), label);
        },
    })));
    return found;
}

/**
 * One (label, callee) vote per label: the first RIP-relative LEA of the label
 * string followed by a direct call into the module's code. ONE linear pass over
 * the module's executable ranges, chunked so it yields to the event loop.
 */
async function collectLabelVotesX64Fast(
    mod: Module | ModuleLike,
    labelAt: Map<number, string>,
    abi: CallAbi,
): Promise<{ label: string; callee: string }[]> {
    const prefix = LEA_ARG1_PREFIX[abi];
    if (prefix === undefined) return [];
    const lo = Number(mod.base.toString());
    const hi = lo + mod.size;
    const targets = new Set<string>([...labelAt.keys()].map((a) => ptr(a).toString()));
    const voted = new Map<string, string>();
    await scanRangesChunked(mod.enumerateRanges("r-x") as ScanRange[], [{
        pattern: prefix,
        onMatch: (site: NativePointer) => {
            try {
                const target = site.add(7 + site.add(3).readS32()).toString();
                if (!targets.has(target)) return;
                const label = labelAt.get(Number(target))!;
                if (voted.has(label)) return;
                const code = new Uint8Array(site.readByteArray(7 + CALL_SEARCH_WINDOW + 5)!);
                const callee = firstCallAfter(code, Number(site.toString()), 0, lo, hi);
                if (callee !== null) voted.set(label, ptr(callee).toString());
            } catch (_e) { /* unreadable tail: skip this site */ }
        },
    }]);
    return [...voted].map(([label, callee]) => ({ label, callee }));
}

async function collectLabelVotesX64(
    mod: Module | ModuleLike,
    labelAt: Map<number, string>,
): Promise<{ label: string; callee: string }[]> {
    const lo = Number(mod.base.toString());
    const hi = lo + mod.size;
    const targets = new Set<number>(labelAt.keys());
    const voted = new Map<string, string>();
    for (const range of mod.enumerateRanges("r-x") as ScanRange[]) {
        for (let off = 0; off < range.size; off += XREF_SCAN_CHUNK_BYTES) {
            if (_isShuttingDownNow()) return [];
            const len = Math.min(XREF_SCAN_CHUNK_BYTES + X64_CHUNK_OVERLAP, range.size - off);
            const at = range.base.add(off);
            let buf: ArrayBuffer | null = null;
            try { buf = at.readByteArray(len); } catch (_e) { buf = null; }
            if (buf !== null) {
                const code = new Uint8Array(buf);
                const va = Number(at.toString());
                const own = Math.min(XREF_SCAN_CHUNK_BYTES, range.size - off);
                for (const ref of findRipLeaRefs(code, va, targets, own)) {
                    const label = labelAt.get(ref.target)!;
                    if (voted.has(label)) continue;
                    const callee = firstCallAfter(code, va, ref.site - va, lo, hi);
                    if (callee !== null) voted.set(label, ptr(callee).toString());
                }
            }
            await yieldToEventLoop();
        }
    }
    return [...voted].map(([label, callee]) => ({ label, callee }));
}

/** Decode the ctx/keylog offsets from the x86-64 prologue at `fn`, or null. */
function decodeCtxOffsetsX64At(
    fn: NativePointer, sslReg: number, moduleName: string,
): { ctxOff: number; cbOff: number } | null {
    try {
        if (!isReadable(fn, 96)) return null;
        return decodeX64CtxKeylogOffsets(new Uint8Array(fn.readByteArray(96)!), sslReg);
    } catch (e) {
        devlog(`[anchor-locator] ${moduleName}: x64 prologue read failed: ${e}`);
        return null;
    }
}

/** ssl_log_secret address from an --offsets entry for `mod` (module name
 *  matched case-insensitively), or null. */
function pinnedSslLogSecret(mod: Module | ModuleLike): NativePointer | null {
    try {
        const all: any = offsets as any;
        if (!all || typeof all !== "object") return null;
        const key = Object.keys(all).find((k) => k.toLowerCase() === mod.name.toLowerCase());
        const v = key === undefined ? undefined : all[key]?.["ssl_log_secret"];
        if (!v || typeof v.address !== "string") return null;
        const addr = v.absolute ? ptr(v.address) : mod.base.add(ptr(v.address));
        return addr.isNull() ? null : addr;
    } catch (_e) {
        return null;
    }
}

/**
 * Tier 4 on x86-64: locate ssl_log_secret in `mod` by label xrefs, then install
 * via the ctx->keylog_callback write (offsets decoded from its prologue) or,
 * failing that, the ABI-aware field dump. `mod` may be a /proc/self/maps
 * ModuleLike (PE images on Wine >= 9 are not Frida modules). Resolves true iff
 * a keylog hook was installed.
 */
export async function runAnchorLocatorX64(
    mod: Module | ModuleLike,
    dumpKeys: DumpKeysCb,
    abi: CallAbi,
): Promise<boolean> {
    const moduleName = mod.name;
    const sslReg = abi === "win64" ? X64_REG.rcx : X64_REG.rdi;

    // Host-resolved RVA (friTap/wine_chromium.py pre-resolves Chromium modules
    // from the PE file on disk and passes it as an --offsets entry): no scan.
    // Accepted only if the ctx/keylog prologue decodes there, so a stale cache
    // entry (or a same-named module of another build) falls back to the scan.
    const pinned = pinnedSslLogSecret(mod);
    if (pinned !== null) {
        const offs = decodeCtxOffsetsX64At(pinned, sslReg, moduleName);
        if (offs !== null) {
            devlog(`[anchor-locator] ${moduleName}: ssl_log_secret @ ${pinned} from --offsets ` +
                `(rva 0x${pinned.sub(mod.base).toString(16)}); no scan needed`);
            return installViaCtxWrite(moduleName, pinned, offs, abi);
        }
        devlog(`[anchor-locator] ${moduleName}: --offsets ssl_log_secret @ ${pinned} does not decode; scanning instead`);
    }

    const started = Date.now();
    devlog(`[anchor-locator] ${moduleName}: x64 label-xref scan of ${(mod.size / (1024 * 1024)).toFixed(1)} MB ` +
        `(abi=${abi}, background, non-blocking)`);
    const labelAt = await findLabelStringsX64(mod);
    if (labelAt.size < 2) {
        devlog(`[anchor-locator] ${moduleName}: only ${labelAt.size} keylog label string(s) present; not BoringSSL`);
        return false;
    }
    // Fast path: native scan for `lea <arg1>, [rip+X]`; the full LEA walk only
    // when that does not yield an agreed callee (label staged in another register).
    let pairs = await collectLabelVotesX64Fast(mod, labelAt, abi);
    if (pickAgreedCallee(pairs) === null) {
        devlog(`[anchor-locator] ${moduleName}: arg-register LEA scan inconclusive after ${Date.now() - started} ms; walking all LEAs`);
        pairs = await collectLabelVotesX64(mod, labelAt);
    }
    devlog(`[anchor-locator] ${moduleName}: x64 xref scan finished in ${Date.now() - started} ms; votes ` +
        (pairs.map((p) => `${p.label}->${p.callee}`).join(", ") || "(none)"));
    const agreed = pickAgreedCallee(pairs);
    if (agreed === null) {
        devlog(`[anchor-locator] ${moduleName}: no ssl_log_secret candidate agreed across >=2 labels`);
        return false;
    }
    if (_isShuttingDownNow()) return false;
    const fn = ptr(agreed);
    devlog(`[anchor-locator] ${moduleName}: ssl_log_secret @ ${fn} (rva 0x${fn.sub(mod.base).toString(16)}, ` +
        `agreed by ${pairs.filter((p) => p.callee === agreed).length}/${pairs.length} labels)`);

    resetReadableCache();
    const offs = decodeCtxOffsetsX64At(fn, sslReg, moduleName);
    if (offs !== null) return installViaCtxWrite(moduleName, fn, offs, abi);
    devlog(`[anchor-locator] ${moduleName}: x64 ctx-offset decode failed; using field-dump fallback`);
    return installViaFieldDump(moduleName, fn, dumpKeys, abi);
}

// Self-register so onAllKeylogTiersMissed() can invoke tier 4 without importing
// any Frida-API module (that module stays Node-unit-testable).
registerBoringSSLTier4(runAnchorLocatorTier4);
