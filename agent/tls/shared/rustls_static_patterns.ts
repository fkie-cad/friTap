// agent/tls/shared/rustls_static_patterns.ts
//
// Key extraction for plain Rust binaries that statically link rustls (no rustls-ffi
// exports, symbols usually stripped). Shared by the legacy (agent/legacy/tls/platforms/
// linux/rustls_linux.ts) and the modern (agent/tls/platforms/linux/rustls_linux.ts)
// Linux rustls hookers.
//
// Targets (both are real, non-inlined functions in release builds):
//  - TLS 1.3: rustls::tls13::key_schedule::KeySchedule::derive_logged_secret(&self, kind,
//    hs_hash, key_log: &dyn KeyLog, client_random: &[u8; 32]) -> OkmBlock. Every logged
//    TLS 1.3 secret (c/s hs traffic, c/s ap traffic, exporter, early) passes through it,
//    whatever KeyLog the application installed (NoKeyLog by default).
//  - TLS 1.2: rustls::tls12::ConnectionSecrets::from_key_exchange(..) -> Result<Self, Error>.
//
// Calling convention: these are Rust-ABI internal functions, and LLVM rewrites their
// signatures (scalar-replaces &self into its Box<dyn HkdfExpander> (data, vtable) pair,
// splits the &dyn KeyLog vtable into its two used method pointers, ...). The argument
// positions below are therefore NOT the source-level ones: they were read off the
// disassembly of each pattern's function (rustls 0.22.4 / 0.23.10 / 0.23.46, ring and
// aws-lc-rs, rustc 1.99, release profile) and belong to that pattern.
//
//  derive_logged_secret, as compiled (arm64 x0..x7 then stack; x64 rdi,rsi,rdx,rcx,r8,r9
//  then stack — so Frida's args[i] index is the same on both):
//    args[0] out: *mut OkmBlock { buf: [u8; 64], used: usize }   (secret = buf[..used])
//    args[1], args[2] self.current (Box<dyn HkdfExpander> data, vtable)
//    args[3] kind: SecretKind (u8, declaration order — see TLS13_SECRET_LABELS)
//    args[4], args[5] hs_hash (ptr, len)
//    args[6] key_log data, args[7] KeyLog::log fn, args[8] KeyLog::will_log fn
//    args[9] client_random: *const [u8; 32]
//
//  from_key_exchange returns Result<ConnectionSecrets, Error> indirectly (arm64: x8, the
//  AAPCS64 indirect-result register; x64: rdi = args[0]). Layout of the Ok value:
//    +0 suite: &'static Tls12CipherSuite (0 = the Err niche), +8 client_random[32],
//    +40 server_random[32], +72 master_secret[48]

import { sendKeylog } from "../../shared/shared_structures.js";
import { toHexString } from "../../shared/shared_functions.js";
import { devlog, devlog_error, log } from "../../util/log.js";
import { normalizeArchKey } from "../../util/process_infos.js";

/** Where a value is found at function entry: Frida's args[i], or a named register. */
export type EntryValue = { arg: number } | { reg: string };

export interface RustlsTls13Layout {
    hook: "tls13_derive_logged_secret";
    out: EntryValue;
    secretKind: EntryValue;
    clientRandom: EntryValue;
}

export interface RustlsTls12Layout {
    hook: "tls12_from_key_exchange";
    out: EntryValue;
}

export interface RustlsStaticPattern {
    id: string;
    arch: "arm64" | "x64";
    /** rustls versions the pattern was validated on (unique match at the right function). */
    validatedOn: string;
    pattern: string;
    /**
     * arm64 only: the pattern anchors on the function BODY; the hook goes on the entry,
     * found by walking back at most this many instructions to its `sub sp, sp, #imm`.
     * (The register-save sequence between entry and body varies between builds.)
     */
    entryBacktrack?: number;
    layout: RustlsTls13Layout | RustlsTls12Layout;
}

const TLS13_LAYOUT_ARGS_0_3_9: RustlsTls13Layout = {
    hook: "tls13_derive_logged_secret", out: { arg: 0 }, secretKind: { arg: 3 }, clientRandom: { arg: 9 },
};

const VALIDATED_ON = "rustls 0.22.4, 0.23.10, 0.23.46 (ring + aws-lc-rs), rustc 1.99, stripped and unstripped release";
const VALIDATED_ON_OLDER_RUSTC = "rustls 0.23.46 (ring), rustc 1.85, stripped and unstripped release";

export const RUSTLS_STATIC_PATTERNS: RustlsStaticPattern[] = [
    {
        // sub sp,sp,#N; stp x29,x30 / x28..x19 saves; add x29,sp,#N; sub w8,w3,#1 (kind-1
        // indexes the label tables); adrp/add x9; and xK,x8,#0xff; adrp/add x8;
        // ldrsw x10,[x9,xK,lsl#2]; ldrb w28,[x8,xK]; ldr x8,[x2,#40] (HkdfExpander vtable).
        // K (x26 / x27) and the load destinations vary between otherwise identical builds.
        id: "rustls_0.23_derive_logged_secret_arm64",
        arch: "arm64",
        validatedOn: VALIDATED_ON,
        pattern: "FF ?? ?? D1 FD 7B ?? A9 FC 6F ?? A9 FA 67 ?? A9 F8 5F ?? A9 F6 57 ?? A9 F4 4F ?? A9 FD ?? ?? 91 68 04 00 51 ?9 ?? ?? ?0 29 ?? ?? 91 ?? 1D 40 92 ?8 ?? ?? ?0 08 ?? ?? 91 ?? 79 B? B8 ?? 69 7? 38 48 14 40 F9",
        layout: TLS13_LAYOUT_ARGS_0_3_9,
    },
    {
        // Body: ldp q1,q2,[x5] (randoms); movi v3.2d,#0 (master_secret = [0; 48]);
        // mov x19,x8 (indirect result); ldr wN,[x4] (ems_seed discriminant); then
        // mov/stp q1,q2 or add. The saves before it differ (x28+fp / fp only / x29,x30,x23).
        id: "rustls_0.23_from_key_exchange_arm64",
        arch: "arm64",
        validatedOn: `${VALIDATED_ON}; ${VALIDATED_ON_OLDER_RUSTC}`,
        pattern: "A1 08 40 AD 03 E4 00 6F F3 03 08 AA 8? 00 40 B9",
        entryBacktrack: 8,
        layout: { hook: "tls12_from_key_exchange", out: { reg: "x8" } },
    },
    {
        // push rbp,r15..r12,rbx; sub rsp,N; mov r12,r9; mov [rsp+N],r8; mov rbp,rdx;
        // mov [rsp+N],rsi; mov rbx,rdi (out); dec cl (kind-1); movzx r14d,cl
        id: "rustls_0.23_derive_logged_secret_x64",
        arch: "x64",
        validatedOn: VALIDATED_ON,
        pattern: "55 41 57 41 56 41 55 41 54 53 48 81 EC ?? ?? 00 00 4D 89 CC 4C 89 44 24 ?? 48 89 D5 48 89 74 24 ?? 48 89 FB FE C9 44 0F B6 F1",
        layout: TLS13_LAYOUT_ARGS_0_3_9,
    },
    {
        // push rbp,r15..r12,rbx; sub rsp,N; mov rax,r8; mov r11,rcx; mov r14,rdx;
        // mov r15,rsi; mov rbx,rdi (out); mov rcx,[rsp+N] (suite); mov rdx,[rsp+N]
        // (randoms); xorps xmm0,xmm0 (master_secret = [0; 48])
        id: "rustls_0.23_from_key_exchange_x64",
        arch: "x64",
        validatedOn: VALIDATED_ON,
        pattern: "55 41 57 41 56 41 55 41 54 53 48 81 EC ?? ?? 00 00 4C 89 C0 49 89 CB 49 89 D6 49 89 F7 48 89 FB 48 8B 8C 24 ?? ?? 00 00 48 8B 94 24 ?? ?? 00 00 0F 57 C0",
        layout: { hook: "tls12_from_key_exchange", out: { arg: 0 } },
    },
    // Older rustc (1.85-era LLVM) codegen of the same two functions; same argument layout.
    // The existing Android librustls built-in patterns are this generation.
    {
        // no frame-pointer setup; mov wK,w3 (kind); adrp/add; and x9,xK,#0xff; adrp/add;
        // ldr x28,[x8,x9,lsl#3] (label table); ldr x8,[x2,#40]
        id: "rustls_0.23_derive_logged_secret_arm64_rustc185",
        arch: "arm64",
        validatedOn: VALIDATED_ON_OLDER_RUSTC,
        pattern: "FF ?? ?? D1 FD 7B ?? A9 FC 6F ?? A9 FA 67 ?? A9 F8 5F ?? A9 F6 57 ?? A9 F4 4F ?? A9 ?? 03 03 2A ?8 ?? ?? ?0 08 ?? ?? 91 ?9 1? 40 92 ?? ?? ?? ?0 ?? ?? ?? 91 ?? 79 69 F8 48 14 40 F9",
        layout: TLS13_LAYOUT_ARGS_0_3_9,
    },
    {
        // ...; mov r13,r9; mov [rsp+N],r8; mov [rsp+N],rcx; mov r14,rdx; mov r12,rsi;
        // mov rbx,rdi (out); movzx eax,cl (kind); shl eax,3
        id: "rustls_0.23_derive_logged_secret_x64_rustc185",
        arch: "x64",
        validatedOn: VALIDATED_ON_OLDER_RUSTC,
        pattern: "55 41 57 41 56 41 55 41 54 53 48 81 EC ?? ?? 00 00 4D 89 CD 4C 89 44 24 ?? 48 89 4C 24 ?? 49 89 D6 49 89 F4 48 89 FB 0F B6 C1 C1 E0 03",
        layout: TLS13_LAYOUT_ARGS_0_3_9,
    },
    {
        // as the x64 entry above, with r15/r12 for rdx/rsi and rdi for the suite load
        id: "rustls_0.23_from_key_exchange_x64_rustc185",
        arch: "x64",
        validatedOn: VALIDATED_ON_OLDER_RUSTC,
        pattern: "55 41 57 41 56 41 55 41 54 53 48 81 EC ?? ?? 00 00 4C 89 C0 49 89 CB 49 89 D7 49 89 F4 48 89 FB 48 8B BC 24 ?? ?? 00 00 48 8B 94 24 ?? ?? 00 00",
        layout: { hook: "tls12_from_key_exchange", out: { arg: 0 } },
    },
];

/** SecretKind (declaration order, rustls 0.21-0.23) → NSS key log label; unlisted kinds are never logged. */
export const TLS13_SECRET_LABELS: { [kind: number]: string } = {
    1: "CLIENT_EARLY_TRAFFIC_SECRET",
    2: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    3: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    4: "CLIENT_TRAFFIC_SECRET_0",
    5: "SERVER_TRAFFIC_SECRET_0",
    6: "EXPORTER_SECRET",
};

const OKM_BLOCK_CAPACITY = 64;
const CLIENT_RANDOM_LEN = 32;
const MASTER_SECRET_LEN = 48;

function readEntryValue(value: EntryValue, args: InvocationArguments, context: CpuContext): NativePointer {
    return "arg" in value ? args[value.arg] : (context as any)[value.reg];
}

/** TLS 1.3 key log line from derive_logged_secret's OkmBlock, or null when not loggable. */
export function tls13KeylogLine(secretKind: number, clientRandom: ArrayBuffer | null,
                                okm: ArrayBuffer | null): string | null {
    const label = TLS13_SECRET_LABELS[secretKind];
    if (!label || !clientRandom || !okm) return null;
    return `${label} ${toHexString(clientRandom)} ${toHexString(okm)}`;
}

/** TLS 1.2 key log line from from_key_exchange's Ok(ConnectionSecrets) at `out`, or null on Err. */
export function tls12KeylogLineAt(out: NativePointer): string | null {
    if (out.isNull() || out.readPointer().isNull()) return null;
    const clientRandom = out.add(8).readByteArray(CLIENT_RANDOM_LEN);
    const masterSecret = out.add(72).readByteArray(MASTER_SECRET_LEN);
    if (!clientRandom || !masterSecret) return null;
    return `CLIENT_RANDOM ${toHexString(clientRandom)} ${toHexString(masterSecret)}`;
}

function tls13KeylogLineAt(out: NativePointer, secretKind: number, clientRandomPtr: NativePointer): string | null {
    if (out.isNull() || clientRandomPtr.isNull()) return null;
    const used = out.add(OKM_BLOCK_CAPACITY).readU64().toNumber();
    if (used === 0 || used > OKM_BLOCK_CAPACITY) return null;
    return tls13KeylogLine(secretKind, clientRandomPtr.readByteArray(CLIENT_RANDOM_LEN), out.readByteArray(used));
}

function emit(line: string | null, what: string): void {
    if (line === null) {
        devlog(`[rustls static] ${what}: nothing to log`);
        return;
    }
    sendKeylog(line);
}

function attachTls13(address: NativePointer, layout: RustlsTls13Layout): void {
    Interceptor.attach(address, {
        onEnter(args) {
            this.out = readEntryValue(layout.out, args, this.context);
            this.secretKind = readEntryValue(layout.secretKind, args, this.context).toUInt32() & 0xff;
            this.clientRandom = readEntryValue(layout.clientRandom, args, this.context);
        },
        onLeave() {
            try {
                emit(tls13KeylogLineAt(this.out, this.secretKind, this.clientRandom), "derive_logged_secret");
            } catch (e) {
                devlog_error(`[rustls static] derive_logged_secret: ${e}`);
            }
        },
    });
}

function attachTls12(address: NativePointer, layout: RustlsTls12Layout): void {
    Interceptor.attach(address, {
        onEnter(args) {
            this.out = readEntryValue(layout.out, args, this.context);
        },
        onLeave() {
            try {
                emit(tls12KeylogLineAt(this.out), "from_key_exchange");
            } catch (e) {
                devlog_error(`[rustls static] from_key_exchange: ${e}`);
            }
        },
    });
}

/** Every match of `pattern` in the module's executable ranges. */
function scanExecutable(module: Module, pattern: string): NativePointer[] {
    const hits: NativePointer[] = [];
    for (const range of module.enumerateRanges("r-x")) {
        try {
            for (const match of Memory.scanSync(range.base, range.size, pattern)) hits.push(match.address);
        } catch (e) {
            devlog_error(`[rustls static] scan of ${range.base} failed: ${e}`);
        }
    }
    return hits;
}

/** `sub sp, sp, #imm{, lsl #12}` (64-bit SUB immediate, Rd = Rn = sp). */
export function isArm64SubSpImmediate(word: number): boolean {
    return ((word & 0xff8003ff) >>> 0) === 0xd10003ff;
}

/**
 * The function entry for a body match at `match`: the nearest `sub sp, sp, #imm` at most
 * `maxInstructions` before it, or null when there is none (then the match is not hooked).
 */
export function arm64EntryBefore(match: NativePointer, maxInstructions: number): NativePointer | null {
    for (let i = 1; i <= maxInstructions; i++) {
        const candidate = match.sub(4 * i);
        if (isArm64SubSpImmediate(candidate.readU32())) return candidate;
    }
    return null;
}

function hookAddressFor(entry: RustlsStaticPattern, match: NativePointer): NativePointer | null {
    return entry.entryBacktrack ? arm64EntryBefore(match, entry.entryBacktrack) : match;
}

export interface RustlsStaticHookResult {
    tls13: boolean;
    tls12: boolean;
}

/**
 * Hook derive_logged_secret / from_key_exchange in `module` by the built-in patterns for
 * this CPU. A pattern is used only when it matches exactly once (an ambiguous match is
 * never hooked). Returns which TLS versions got a hook, so callers can fall back.
 */
export function installRustlsStaticPatternHooks(module: Module | null,
                                                patterns: RustlsStaticPattern[] = RUSTLS_STATIC_PATTERNS): RustlsStaticHookResult {
    const result: RustlsStaticHookResult = { tls13: false, tls12: false };
    if (!module) return result;
    const arch = normalizeArchKey(Process.arch);
    for (const entry of patterns.filter((p) => p.arch === arch)) {
        const isTls13 = entry.layout.hook === "tls13_derive_logged_secret";
        if (isTls13 ? result.tls13 : result.tls12) continue;
        const hits = scanExecutable(module, entry.pattern);
        if (hits.length !== 1) {
            devlog(`[rustls static] ${entry.id}: ${hits.length} matches in ${module.name}; not hooking`);
            continue;
        }
        let target: NativePointer | null = null;
        try {
            target = hookAddressFor(entry, hits[0]);
            if (target === null) {
                devlog(`[rustls static] ${entry.id}: no function entry before ${hits[0]}; not hooking`);
                continue;
            }
            if (entry.layout.hook === "tls13_derive_logged_secret") attachTls13(target, entry.layout);
            else attachTls12(target, entry.layout);
        } catch (e) {
            devlog_error(`[rustls static] attach ${entry.id} @ ${target ?? hits[0]}: ${e}`);
            continue;
        }
        if (isTls13) result.tls13 = true; else result.tls12 = true;
        log(`[*] ${module.name}: keylog hooks installed via pattern (${entry.id} @ ${target})`);
    }
    return result;
}
