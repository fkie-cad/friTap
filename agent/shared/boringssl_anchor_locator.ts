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

import { log, devlog, devlog_debug, _isShuttingDownNow } from "../util/log.js";
import { sendKeylog } from "./shared_structures.js";
import {
    isLDRimmU64, isCBZ64, isCBNZ64, decodeLDRU64Imm, regRd, regRn,
    isADDimm64, decodeADDImm12, isAnyCall, isBL, movzW, writesReg,
    movRegSource, movRegDest, directBranchOffset, endsFallThrough, isFunctionPrologueWord,
} from "./arm64.js";
import {
    findAnchorStringsAsync, findStringLoadSitesAsync, firstCallTargetForward,
    blTarget, outlinedStubBody, REGISTER_SAVE_STUB, functionByteLength, readInstructionWords,
    type FunctionBoundsSource, type ScanStatus,
} from "./arm64_xref.js";
import { DECODE_UNREADABLE, isDecoded, type Decoded, type DecodeVerdict } from "./keylog_guards.js";
import {
    findRange, isReadable, isWritable, readableByteCount, safeReadPointer, resetReadableCache,
} from "../util/safe_memory.js";
import {
    attachSslLogSecretHook, attachSslLogSecretOnce, claimForLiveSslLogSecretHook, claimKeylogHook, isSslLogSecretHooked,
    keylogHookOwner, registerBoringSSLTier4, tryAttach,
} from "./boringssl_keylog_outcome.js";
import type { DumpKeysCb } from "./boringssl_symbol_hook.js";
import { argAt, callAbiForModule, type CallAbi } from "./call_abi.js";
import { scanRangesChunked, yieldToEventLoop, XREF_SCAN_CHUNK_BYTES, type ScanRange } from "./arm64_xref.js";
import {
    CALL_SEARCH_WINDOW, decodeX64CtxKeylogOffsets, findRipLeaRefs, firstCallAfter, LEA_ARG1_PREFIX,
} from "./x64_xref.js";
import { X64 } from "./x64_insn.js";
import { findModuleOrPeImage, type ModuleLike } from "../util/proc_maps.js";
import { toHexPattern } from "../util/hex.js";
import { makeWin64ToSysvThunk } from "./win64_thunk.js";
import { offsets } from "../fritap_agent.js";
import { ehFrameTableFor } from "./eh_frame.js";
import {
    hasLearnedMiss, learnedFunction, learnedMissName, missFingerprint,
    rejectLearnedFunction, reportLearned, reportLearnedMisses,
} from "./learned_module_cache.js";
import { type CacheModule, mappingAddressKey, mappingKey, memoizePerMapping } from "./module_mapping.js";

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

// ---- ssl->s3 / s3->client_random layout (the P1 client_random join key) ----
//
// After the keylog_callback early return and the CBB setup, ssl_log_secret
// reads ssl->s3 and passes &s3->client_random to the hex writer:
//     mov  x19, x0              ; ssl kept in a callee-saved register
//     ...  (CBB_init / CBB_add_bytes calls)
//     ldr  x8, [x19, #s3Off]    ; x8 = ssl->s3
//     add  x1, x8, #crOff       ; x1 = s3->client_random
//     mov  w2, #0x20            ; SSL3_RANDOM_SIZE (optional corroboration)
// decodeSslLogSecretLayout() follows the ssl register through such moves and
// accepts exactly one distinct (s3Off, crOff) pair; anything ambiguous is null.

/** Upper bound on the body words scanned when the function end is unknown. */
export const SSL_LOG_SECRET_MAX_WORDS = 256;
const MIN_S3_OFFSET = 0x8;
const MAX_S3_OFFSET = 0x400;
const MIN_CLIENT_RANDOM_OFFSET = 0x10;
const MAX_CLIENT_RANDOM_OFFSET = 0x200;
// How far after the s3 load the `add xB, xA, #crOff` may appear.
const CLIENT_RANDOM_ADD_WINDOW = 16;
// Extra words after the add that may carry the `mov w2, #0x20` length argument.
const LENGTH_ARG_WINDOW = 4;
const LENGTH_ARG_REG = 2;
const SSL3_RANDOM_SIZE = 0x20;
// AAPCS64: x0..x18 are caller-saved, so a call clobbers any ssl alias there.
const LAST_CALLER_SAVED_REG = 18;

/** Decoded ssl->s3 / s3->client_random offsets (lengthArgSeen = `mov w2,#0x20` nearby). */
export interface SslLogSecretLayout { s3Off: number; crOff: number; lengthArgSeen: boolean; }

/** True when `w` is a call and `reg` is caller-saved (its value does not survive). */
function clobbersCallerSavedReg(w: number, reg: number): boolean {
    return isAnyCall(w) && reg <= LAST_CALLER_SAVED_REG;
}

// The ssl aliases are a bitmask over x0..x30 (bit N = xN holds the ssl pointer).
const SSL_ARG_MASK = 1; // only x0 on entry
const XZR = 31;

function holdsSsl(aliasMask: number, reg: number): boolean {
    return reg < XZR && ((aliasMask >>> reg) & 1) === 1;
}

/**
 * Words of the outlined stub each BL of the window calls (null = not a BL, or
 * unknown). Lets the alias flow step through a stub instead of treating it as
 * a real call that clobbers every caller-saved alias.
 */
export type OutlinedStubWordsAt = (wordIndex: number) => number[] | null;

const LINK_REG = 30;

/** Aliases after a BL into a register-save/move stub: run its body, then drop x30. */
function sslAliasesAfterStubCall(aliasMask: number, stubBody: number[]): number {
    const after = stubBody.reduce((mask, w) => sslAliasesAfter(mask, w), aliasMask);
    return (after & ~(1 << LINK_REG)) >>> 0;
}

/** The validated body of each word's stub callee, or null where the word is no such call. */
function stubBodiesOf(words: number[], stubWordsAt?: OutlinedStubWordsAt): (number[] | null)[] {
    return words.map((w, i) => {
        if (stubWordsAt === undefined || !isBL(w >>> 0)) return null;
        const stub = stubWordsAt(i);
        return stub === null ? null : outlinedStubBody(stub, REGISTER_SAVE_STUB);
    });
}

/** Aliases after executing `w`: drop overwritten registers, add `mov xD, <alias>` targets. */
function sslAliasesAfter(aliasMask: number, w: number): number {
    const source = movRegSource(w);
    const dest = movRegDest(w);
    let next = aliasMask;
    for (let reg = 0; reg < XZR; reg++) {
        if (holdsSsl(next, reg) && (writesReg(w, reg) || clobbersCallerSavedReg(w, reg))) next &= ~(1 << reg);
    }
    if (source !== null && dest !== null && dest !== XZR && holdsSsl(aliasMask, source)) next |= 1 << dest;
    return next >>> 0;
}

/** Word indices that may execute after word `i` (fall-through and/or direct branch). */
function successorIndices(words: number[], i: number): number[] {
    const w = words[i] >>> 0;
    const successors = endsFallThrough(w) ? [] : [i + 1];
    const branch = directBranchOffset(w);
    if (branch !== null) successors.push(i + branch / 4);
    return successors.filter((s) => s >= 0 && s < words.length);
}

/**
 * Must-alias dataflow over the scanned words: for each word, the registers that
 * hold `ssl` on EVERY path from the entry that stays inside the window (null =
 * not reached). Following branches matters because the s3 load is often laid
 * out after an error path that reuses the alias register (e.g. `mov w19, wzr`).
 */
function sslAliasesAtEachWord(words: number[], stubBodies: (number[] | null)[] = []): (number | null)[] {
    const before: (number | null)[] = new Array(words.length).fill(null);
    if (words.length === 0) return before;
    before[0] = SSL_ARG_MASK;
    const worklist = [0];
    while (worklist.length > 0) {
        const i = worklist.pop()!;
        const stub = stubBodies[i] ?? null;
        const after = stub === null
            ? sslAliasesAfter(before[i]!, words[i] >>> 0)
            : sslAliasesAfterStubCall(before[i]!, stub);
        for (const s of successorIndices(words, i)) {
            const merged = before[s] === null ? after : (before[s]! & after) >>> 0;
            if (merged !== before[s]) { before[s] = merged; worklist.push(s); }
        }
    }
    return before;
}

/** `ldr xA, [alias, #s3Off]` with a plausible s3Off that is not the ctx offset -> s3Off. */
function s3LoadOffset(w: number, aliasMask: number, ctxOff: number): number | null {
    if (!isLDRimmU64(w) || !holdsSsl(aliasMask, regRn(w))) return null;
    const off = decodeLDRU64Imm(w);
    if (off === ctxOff || off < MIN_S3_OFFSET || off > MAX_S3_OFFSET) return null;
    return off;
}

/** The `add xB, xA, #crOff` following the s3 load, before xA is overwritten. */
function findClientRandomAdd(
    words: number[], loadIndex: number, s3Reg: number,
): { crOff: number; addIndex: number } | null {
    const last = Math.min(words.length - 1, loadIndex + CLIENT_RANDOM_ADD_WINDOW);
    for (let i = loadIndex + 1; i <= last; i++) {
        const w = words[i] >>> 0;
        if (isADDimm64(w) && regRn(w) === s3Reg) {
            const crOff = decodeADDImm12(w);
            if (crOff >= MIN_CLIENT_RANDOM_OFFSET && crOff <= MAX_CLIENT_RANDOM_OFFSET) return { crOff, addIndex: i };
        }
        if (writesReg(w, s3Reg) || clobbersCallerSavedReg(w, s3Reg) || endsFallThrough(w)) return null;
    }
    return null;
}

/** True when `mov w2, #0x20` (the 32-byte client_random length) sits in [from, to]. */
function lengthArgBetween(words: number[], from: number, to: number): boolean {
    for (let i = from; i <= Math.min(to, words.length - 1); i++) {
        if (movzW(words[i] >>> 0, LENGTH_ARG_REG) === SSL3_RANDOM_SIZE) return true;
    }
    return false;
}

/** Every (s3 load, client_random add) pair reachable from the ssl argument. */
function collectSslLayoutCandidates(
    words: number[], ctxOff: number, stubWordsAt?: OutlinedStubWordsAt,
): SslLogSecretLayout[] {
    const window = words.slice(0, SSL_LOG_SECRET_MAX_WORDS);
    const aliasesAt = sslAliasesAtEachWord(window, stubBodiesOf(window, stubWordsAt));
    const found: SslLogSecretLayout[] = [];
    for (let i = 0; i < window.length; i++) {
        const w = window[i] >>> 0;
        const s3Off = aliasesAt[i] === null ? null : s3LoadOffset(w, aliasesAt[i]!, ctxOff);
        const add = s3Off === null ? null : findClientRandomAdd(window, i, regRd(w));
        if (s3Off !== null && add !== null) {
            const lengthArgSeen = lengthArgBetween(window, i, add.addIndex + LENGTH_ARG_WINDOW);
            found.push({ s3Off, crOff: add.crOff, lengthArgSeen });
        }
    }
    return found;
}

/**
 * Decode {s3Off, crOff} from ssl_log_secret's body words (up to
 * SSL_LOG_SECRET_MAX_WORDS, or fewer when the function end is known). Pure, so
 * it is unit-testable without Frida. `ctxOff` (from decodeCtxKeylogOffsets) is
 * excluded as an s3 candidate. Returns null when no pair is found or when two
 * DIFFERENT pairs are: a wrong layout would stamp the wrong client_random.
 * `stubWordsAt` (optional) supplies the callee words of each BL so calls into
 * outlined register-save stubs (`mov x19, x0; ...; ret`) keep the ssl alias.
 */
export function decodeSslLogSecretLayout(
    words: number[], ctxOff: number, stubWordsAt?: OutlinedStubWordsAt,
): SslLogSecretLayout | null {
    const candidates = collectSslLayoutCandidates(words, ctxOff, stubWordsAt);
    if (candidates.length === 0) return null;
    const { s3Off, crOff } = candidates[0];
    if (candidates.some((c) => c.s3Off !== s3Off || c.crOff !== crOff)) return null;
    return { s3Off, crOff, lengthArgSeen: candidates.some((c) => c.lengthArgSeen) };
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

export { DECODE_UNREADABLE };
export type { Decoded, DecodeVerdict };

/**
 * Read up to PROLOGUE_WORDS instruction words at `addr` and decode the ctx
 * offsets. Range-checked because enumerateSymbols/xref can hand back addresses
 * that are not fully mapped, and a fault here is fatal.
 */
function deriveOffsetsAt(addr: NativePointer): Decoded<{ ctxOff: number; cbOff: number }> {
    try {
        const words: number[] = [];
        for (let i = 0; i < PROLOGUE_WORDS; i++) {
            const at = addr.add(i * 4);
            if (!isReadable(at, 4)) return DECODE_UNREADABLE;
            words.push(at.readU32());
        }
        return decodeCtxKeylogOffsets(words);
    } catch (e) {
        devlog(`[anchor-locator] prologue decode failed: ${e}`);
        return DECODE_UNREADABLE;
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
    // `ssl` is the callback's first argument (const SSL *); it lets sendKeylog
    // note the line's client_random for this SSL* (ssl_identity.ts).
    const emitKeylogLine = (linePtr: NativePointer, ssl?: NativePointer): void => {
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
            if (line) sendKeylog(line, ssl, moduleName);
        } catch (e) {
            devlog(`[anchor-locator] ${moduleName}: keylog callback error: ${e}`);
        }
    };
    const keylogCb = new NativeCallback(function (ssl: NativePointer, linePtr: NativePointer) {
        emitKeylogLine(linePtr, ssl);
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
        const range = findRange(fn);
        if (range === null || !range.protection.includes("x")) {
            log(`[-] ${moduleName}: ctx+0x${cbOff.toString(16)} holds ${fn}, which is not code; leaving it alone.`);
            return;
        }
        try {
            Interceptor.attach(fn, {
                onEnter(args: InvocationArguments) {
                    // keylog_callback(const SSL *ssl, const char *line)
                    emitKeylogLine(
                        abi === null ? args[1] : argAt(this.context, abi, 1),
                        abi === null ? args[0] : argAt(this.context, abi, 0),
                    );
                },
            });
            log(`[*] ${moduleName}: the app already sets a keylog callback (${fn}); hooked it instead of replacing it`);
        } catch (e) {
            log(`[-] ${moduleName}: could not hook the app's keylog callback at ${fn}: ${e}`);
        }
    };
    const attached = attachSslLogSecretOnce(fnAddr, "anchor", () => tryAttach(`[anchor-locator] ${moduleName}: (ctx-write)`, fnAddr, {
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
        }));
    if (!attached) return false;
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
    arm64Mod: Module | null = null,
): boolean {
    // A mid-function attach (mis-voted callee) can crash the target; only hook a real entry.
    if (arm64Mod !== null && !isPlausibleFunctionEntry(fnAddr, ehFrameTableFor(arm64Mod))) {
        devlog(`[anchor-locator] ${moduleName}: ${fnAddr} is not a function entry (eh_frame/prologue); field dump skipped`);
        return false;
    }
    if (!attachSslLogSecretHook(fnAddr, "anchor", dumpKeys, moduleName, abi)) return false;
    log(`[*] ${moduleName}: keylog hooks installed via anchor-locator (field dump)`);
    return true;
}

/** arm64: `addr` starts a function per eh_frame bounds, or its first word is a prologue word. */
export function isPlausibleFunctionEntry(addr: NativePointer, functions: FunctionBoundsSource | null): boolean {
    const fn = functions?.bounds(addr) ?? null;
    if (fn !== null && fn.start.equals(addr)) return true;
    try { return isFunctionPrologueWord(addr.readU32()); } catch (_e) { return false; }
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
async function locateSslLogSecret(mod: Module, moduleName: string): Promise<SslLogSecretScan> {
    const status: ScanStatus = { complete: true };
    const modStart = mod.base;
    const modEnd = mod.base.add(mod.size);
    const started = Date.now();
    devlog(`[anchor-locator] ${moduleName}: scanning ${codeMegabytes(mod)} MB of code for ` +
        `${BORINGSSL_KEYLOG_LABELS.length} keylog label xrefs (background, non-blocking)`);

    const strAddrs = await findAnchorStringsAsync(mod, BORINGSSL_KEYLOG_LABELS.map((l) => l + "\u0000"),
        XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, status);
    const labels: string[] = [];
    const targets: NativePointer[] = [];
    strAddrs.forEach((a, i) => { if (a !== null) { labels.push(BORINGSSL_KEYLOG_LABELS[i]); targets.push(a); } });

    const sites = targets.length > 0
        ? await findStringLoadSitesAsync(mod, targets, XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, undefined, status)
        : [];
    const functions = ehFrameTableFor(mod) ?? undefined;
    const pairs = collectLabelVotes(labels, sites,
        (site) => firstCallTargetForward(site, modEnd, modStart, modEnd, functions));
    devlog(`[anchor-locator] ${moduleName}: xref scan finished in ${Date.now() - started} ms ` +
        `(${targets.length} label string(s), ${pairs.length} resolved a call)`);

    devlog(`[anchor-locator] ${moduleName}: votes ` +
        (pairs.map((p) => `${p.label}->${p.callee}`).join(", ") || "(none)"));

    // No label string at all may mean unreadable rodata, not "no BoringSSL".
    const missIsReliable = targets.length > 0 && status.complete;
    const agreed = pickAgreedCallee(pairs);
    if (agreed === null) {
        devlog(`[anchor-locator] ${moduleName}: no ssl_log_secret candidate agreed across ` +
            `>=2 labels (${pairs.length} label(s) resolved a call)`);
        return { found: null, missIsReliable };
    }
    devlog(`[anchor-locator] ${moduleName}: ssl_log_secret candidate @ ${agreed} ` +
        `(agreed by ${pairs.filter((p) => p.callee === agreed).length}/${pairs.length} label xref(s))`);
    return { found: ptr(agreed), missIsReliable };
}

// One xref scan per loaded module, shared by tier 4 and locateSslLayout(), so
// a concurrent caller awaits the scan already in flight instead of starting a
// second one.
const sslLogSecretByModule = new Map<string, Promise<NativePointer | null>>();

export const LEARNED_SSL_LOG_SECRET = "boringssl.ssl_log_secret";
export const LEARNED_SSL_LOG_SECRET_MISS = learnedMissName(LEARNED_SSL_LOG_SECRET);
/** Bump whenever locateSslLogSecret's algorithm changes, so cached misses are rescanned. */
export const LOCATOR_REVISION = 1;
/** Miss-marker value: a cached miss only holds for the labels and algorithm that produced it. */
export const SSL_LOG_SECRET_MISS_FINGERPRINT = missFingerprint(
    ["labels", ...BORINGSSL_KEYLOG_LABELS, "revision", String(LOCATOR_REVISION)]);

/** One label-xref scan: the agreed callee, and whether a null result proves a miss. */
export interface SslLogSecretScan {
    found: NativePointer | null;
    missIsReliable: boolean;
}

/** What locateSslLogSecretCached() needs besides the learned cache (injectable for tests). */
export interface SslLogSecretSources {
    decodes: (fnAddr: NativePointer) => DecodeVerdict;
    scan: (mod: Module, moduleName: string) => Promise<SslLogSecretScan>;
}

function defaultSslLogSecretSources(mod: CacheModule): SslLogSecretSources {
    return {
        decodes: (fnAddr) => sslLogSecretDecodes(mod, fnAddr),
        scan: locateSslLogSecret,
    };
}

/**
 * True when `fnAddr` in `mod` decodes as ssl_log_secret. Either decode confirms
 * it: the ctx-write install needs the ctx/keylog offsets, but the field-dump
 * install only reads the call's arguments, so a body whose s3/client_random
 * layout decodes is hookable (and cacheable) too.
 */
export function sslLogSecretDecodes(mod: CacheModule, fnAddr: NativePointer): DecodeVerdict {
    const offs = memoizedCtxKeylogOffsets(mod, fnAddr, deriveOffsetsAt);
    if (isDecoded(offs)) return true;
    const module = loadedModuleFor(mod);
    const layout = module === null ? null : sslLayoutAt(module, fnAddr);
    if (isDecoded(layout)) return true;
    // An unread decoder might have matched: no verdict either way.
    return offs === DECODE_UNREADABLE || layout === DECODE_UNREADABLE ? null : false;
}

/** The learned ssl_log_secret while it still decodes; a stale entry is dropped. null means "scan". */
export function validatedLearnedSslLogSecret(mod: CacheModule, decodes: (fnAddr: NativePointer) => DecodeVerdict,
                                             logPrefix: string): NativePointer | null {
    const fnAddr = learnedFunction(mod, LEARNED_SSL_LOG_SECRET);
    if (fnAddr === null) return null;
    const verdict = decodes(fnAddr);
    if (verdict === true) return fnAddr;
    if (verdict === null) {
        // A transient unreadable/short read proves nothing: keep the entry.
        devlog(`${logPrefix}: learned ssl_log_secret @ ${fnAddr} could not be read; scanning instead`);
        return null;
    }
    rejectLearnedFunction(mod, LEARNED_SSL_LOG_SECRET);
    devlog(`${logPrefix}: learned ssl_log_secret @ ${fnAddr} does not decode; scanning instead`);
    return null;
}

/** Cache `fnAddr` as this build's ssl_log_secret iff it decodes (anything else would only be rejected later). */
export function reportDecodedSslLogSecret(mod: CacheModule, fnAddr: NativePointer,
                                          decodes: (fnAddr: NativePointer) => DecodeVerdict): boolean {
    if (decodes(fnAddr) !== true) return false;
    reportLearned(mod, { functions: { [LEARNED_SSL_LOG_SECRET]: fnAddr } });
    return true;
}

/** The loaded Module behind a cache handle (eh_frame bounds and stub reads need the real one). */
function loadedModuleFor(mod: CacheModule): Module | null {
    try {
        const module = Process.findModuleByAddress(mod.base);
        return module !== null && module.base.equals(mod.base) ? module : null;
    } catch (_e) {
        return null;
    }
}

// Body decodes (misses included) are kept per mapping + address: validation and
// install both need them. An unreadable decode is never kept, so a transient fault does not stick.
type CtxKeylogOffsets = { ctxOff: number; cbOff: number };
const ctxKeylogOffsetsByAddress = new Map<string, CtxKeylogOffsets | null>();
const sslLayoutByAddress = new Map<string, SslLogSecretBodyLayout | null>();

function memoizedPerAddress<T>(memo: Map<string, T | null>, mod: CacheModule, fnAddr: NativePointer,
                               decode: (fnAddr: NativePointer) => Decoded<T>): Decoded<T> {
    const key = mappingAddressKey(fnAddr, mappingKey(mod));
    const known = memo.get(key);
    if (known !== undefined) return known;
    const decoded = decode(fnAddr);
    if (decoded !== DECODE_UNREADABLE) memo.set(key, decoded);
    return decoded;
}

/** Memoized decode(fnAddr) of the ctx/keylog offsets, keyed by `mod`'s mapping and the address. */
export function memoizedCtxKeylogOffsets(mod: CacheModule, fnAddr: NativePointer,
                                         decode: (fnAddr: NativePointer) => Decoded<CtxKeylogOffsets>):
        Decoded<CtxKeylogOffsets> {
    return memoizedPerAddress(ctxKeylogOffsetsByAddress, mod, fnAddr, decode);
}

export function ctxKeylogOffsetsAt(mod: CacheModule, fnAddr: NativePointer): CtxKeylogOffsets | null {
    const offs = memoizedCtxKeylogOffsets(mod, fnAddr, deriveOffsetsAt);
    return isDecoded(offs) ? offs : null;
}

async function resolveSslLogSecret(mod: Module, moduleName: string,
                                   sources: SslLogSecretSources): Promise<NativePointer | null> {
    const learned = validatedLearnedSslLogSecret(mod, sources.decodes, `[anchor-locator] ${moduleName}`);
    if (learned !== null) {
        devlog(`[anchor-locator] ssl_log_secret for ${moduleName} from learned cache @ ${learned}; no scan needed`);
        return learned;
    }
    if (hasLearnedMiss(mod, LEARNED_SSL_LOG_SECRET_MISS, SSL_LOG_SECRET_MISS_FINGERPRINT)) {
        devlog_debug(`[anchor-locator] ${moduleName}: learned cache records no ssl_log_secret in this build; scan skipped`);
        return null;
    }
    const { found, missIsReliable } = await sources.scan(mod, moduleName);
    if (found === null) {
        reportLearnedMisses(mod, { [LEARNED_SSL_LOG_SECRET_MISS]: SSL_LOG_SECRET_MISS_FINGERPRINT },
            { complete: missIsReliable });
        return null;
    }
    reportDecodedSslLogSecret(mod, found, sources.decodes);
    return found;
}

/** Memoized ssl_log_secret lookup (learned cache, else locateSslLogSecret): at most one scan per loaded module. */
export function locateSslLogSecretCached(mod: Module, moduleName: string,
                                         sources: SslLogSecretSources = defaultSslLogSecretSources(mod)):
        Promise<NativePointer | null> {
    return memoizePerMapping(sslLogSecretByModule, mod, () => resolveSslLogSecret(mod, moduleName, sources));
}

/** Word count to decode at ssl_log_secret: the eh_frame function size, capped. */
function sslLogSecretWordCount(mod: Module, fnAddr: NativePointer): number {
    const bytes = functionByteLength(fnAddr, ehFrameTableFor(mod), SSL_LOG_SECRET_MAX_WORDS * 4);
    return Math.max(1, Math.floor(bytes / 4));
}

export { readableByteCount, readInstructionWords };

/** Reads the in-module callee words of each BL in `words` (laid out from `fnAddr`). */
function stubWordsReader(mod: Module, fnAddr: NativePointer, words: number[]): OutlinedStubWordsAt {
    const modEnd = mod.base.add(mod.size);
    const stubWords = REGISTER_SAVE_STUB.maxBodyWords + 1;
    return (i) => {
        const target = blTarget(fnAddr.add(i * 4), words[i] >>> 0);
        if (target.compare(mod.base) < 0 || target.add(stubWords * 4).compare(modEnd) > 0) return null;
        return readInstructionWords(target, stubWords);
    };
}

/** Decoded ssl_log_secret layout; ctxOff is null when the ctx/keylog prologue did not decode. */
export interface SslLogSecretBodyLayout extends SslLogSecretLayout { ctxOff: number | null; }

// No ctx offset to exclude from the s3 candidates.
const UNKNOWN_CTX_OFFSET = -1;

/**
 * Decode the s3/client_random layout from ssl_log_secret's body words. The ctx
 * offset is only excluded as an s3 candidate, so a body whose ctx/keylog check
 * sits past PROLOGUE_WORDS (e.g. libsignal_jni: stack-protector prologue) still decodes.
 */
export function decodeSslLayoutFromWords(words: number[], stubWordsAt?: OutlinedStubWordsAt): SslLogSecretBodyLayout | null {
    const ctx = decodeCtxKeylogOffsets(words.slice(0, PROLOGUE_WORDS));
    const layout = decodeSslLogSecretLayout(words, ctx?.ctxOff ?? UNKNOWN_CTX_OFFSET, stubWordsAt);
    return layout === null ? null : { ...layout, ctxOff: ctx?.ctxOff ?? null };
}

/** Memoized s3/client_random layout decode of the ssl_log_secret body at `fnAddr`. */
function sslLayoutAt(mod: Module, fnAddr: NativePointer): Decoded<SslLogSecretBodyLayout> {
    return memoizedPerAddress(sslLayoutByAddress, mod, fnAddr, () => {
        const wanted = sslLogSecretWordCount(mod, fnAddr);
        const words = readInstructionWords(fnAddr, wanted);
        const layout = decodeSslLayoutFromWords(words, stubWordsReader(mod, fnAddr, words));
        // A miss on a short read may be the read's fault, not the body's.
        return layout === null && words.length < wanted ? DECODE_UNREADABLE : layout;
    });
}

/** Decode {s3Off, crOff, ctxOff} from the located ssl_log_secret body, or null. */
function decodeSslLayoutAt(mod: Module, moduleName: string, fnAddr: NativePointer): SslLogSecretBodyLayout | null {
    const layout = sslLayoutAt(mod, fnAddr);
    if (!isDecoded(layout)) {
        devlog(`[anchor-locator] ${moduleName}: ssl layout not decoded at ${fnAddr}`);
        return null;
    }
    const ctxText = layout.ctxOff === null ? "unknown" : `0x${layout.ctxOff.toString(16)}`;
    devlog(`[anchor-locator] ${moduleName}: ssl layout at ${fnAddr}: s3Off=0x${layout.s3Off.toString(16)} ` +
        `crOff=0x${layout.crOff.toString(16)} ctxOff=${ctxText} lengthArg=${layout.lengthArgSeen}`);
    return layout;
}

/**
 * LOCATE-ONLY entry point: find ssl_log_secret in `moduleName` (sharing the
 * tier-4 scan) and decode the ssl->s3 / s3->client_random layout from it.
 * Writes nothing to SSL_CTX and attaches no hook, so it is safe to call when
 * keylogging is disabled. arm64 only (x64 is left to overlap learning).
 * Never throws; resolves null on any miss.
 */
export async function locateSslLayout(moduleName: string): Promise<SslLogSecretBodyLayout | null> {
    if (Process.arch !== "arm64") return null;
    try {
        const mod = Process.findModuleByName(moduleName);
        if (mod === null) return null;
        const fnAddr = await locateSslLogSecretCached(mod, moduleName);
        if (fnAddr === null || _isShuttingDownNow()) return null;
        return decodeSslLayoutAt(mod, moduleName, fnAddr);
    } catch (e) {
        devlog(`[anchor-locator] ${moduleName}: ssl layout locate failed: ${e}`);
        return null;
    }
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

    const sslLogSecret = await locateSslLogSecretCached(mod, moduleName);
    if (sslLogSecret === null) return false;
    // The scan above yields to the JS loop; a detach/dispose that ran meanwhile
    // has already restored the keylog fields, so installing now would leave a
    // hook (and possibly a ctx write) behind that nothing will ever undo.
    if (_isShuttingDownNow()) {
        devlog(`[anchor-locator] ${moduleName}: shutdown during ssl_log_secret scan; not installing`);
        return false;
    }
    if (isSslLogSecretHooked(sslLogSecret)) {
        devlog(`[anchor-locator] ${moduleName}: ssl_log_secret @ ${sslLogSecret} is already hooked; not hooking it again`);
        // The live hook is another tier's; hand it the module before this
        // success makes the caller claim it for tier 4 and mute that hook.
        claimForLiveSslLogSecretHook(moduleName, sslLogSecret, "anchor");
        return true;
    }

    resetReadableCache();
    const offs = ctxKeylogOffsetsAt(mod, sslLogSecret);
    if (offs !== null) {
        return installViaCtxWrite(moduleName, sslLogSecret, offs);
    }
    devlog(`[anchor-locator] ${moduleName}: ctx-offset decode failed; using field-dump fallback`);
    return installViaFieldDump(moduleName, sslLogSecret, dumpKeys, null, mod);
}

// ---- observe-only (no keylog) ---------------------------------------------

/** Told the SSL* of every ssl_log_secret call; never sees a secret. */
export type SslLogSecretObserver = (ssl: NativePointer) => void;

// One run (locate + hook) per module; a repeat caller gets the same promise.
const observeOnlyRuns = new Map<string, Promise<boolean>>();

/**
 * Entry hook on ssl_log_secret that only hands `ssl` to `observe`. Unlike the
 * ctx-write path it writes nothing into SSL_CTX and BoringSSL formats no line;
 * unlike the field dump it never touches the secret. The entry runs on every
 * handshake secret even when ctx->keylog_callback is NULL (that check is
 * inside the function). Once per module via observeOnlyRuns.
 */
function installSslLogSecretObserver(
    moduleName: string, fnAddr: NativePointer, observe: SslLogSecretObserver,
): boolean {
    try {
        Interceptor.attach(fnAddr, {
            onEnter(args: InvocationArguments) {
                if (_isShuttingDownNow()) return;
                try {
                    observe(args[0]);
                } catch (_e) { /* observation is best-effort */ }
            },
        });
    } catch (e) {
        devlog(`[anchor-locator] ${moduleName}: Interceptor.attach (observe-only) failed: ${e}`);
        return false;
    }
    devlog(`[anchor-locator] ${moduleName}: observe-only ssl_log_secret hook @ ${fnAddr} (no keylog)`);
    return true;
}

/**
 * Locate ssl_log_secret (sharing the tier-4 scan) and install the observe-only
 * entry hook, with or without -k. A module whose keylog hook is owned by a
 * tier already reports SSL* through sendKeylog, so it is skipped. arm64 only;
 * --pairip-safe gating is the caller's job. Once per module; never throws.
 */
export function runAnchorLocatorObserveOnly(moduleName: string, observe: SslLogSecretObserver): Promise<boolean> {
    let run = observeOnlyRuns.get(moduleName);
    if (run === undefined) {
        run = locateAndObserve(moduleName, observe);
        observeOnlyRuns.set(moduleName, run);
    }
    return run;
}

async function locateAndObserve(moduleName: string, observe: SslLogSecretObserver): Promise<boolean> {
    if (Process.arch !== "arm64" || keylogHookOwner(moduleName) !== undefined) return false;
    try {
        const mod = Process.findModuleByName(moduleName);
        if (mod === null) return false;
        const fnAddr = await locateSslLogSecretCached(mod, moduleName);
        if (fnAddr === null || _isShuttingDownNow() || keylogHookOwner(moduleName) !== undefined) return false;
        return installSslLogSecretObserver(moduleName, fnAddr, observe);
    } catch (e) {
        devlog(`[anchor-locator] ${moduleName}: observe-only locate failed: ${e}`);
        return false;
    }
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
    const sslReg = abi === "win64" ? X64.rcx : X64.rdi;

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
