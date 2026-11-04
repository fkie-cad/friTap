// agent/ipsec/libs/strongswan_keys.ts
//
// strongSwan IKEv2 + ESP (CHILD_SA) key extraction from a STOCK, STRIPPED
// charon (the build Debian/Ubuntu ship). The key-derivation routines are not
// exported — in libcharon they are static METHOD()s of keymat_v2_t
// (derive_ike_keys / derive_child_keys) — so nothing can be hooked by symbol.
// They are located instead by the unique DBG4/DBG format-string literals they
// reference, via the generic string-anchor locator (shared/string_anchor_functions.ts).
//
// WHY THE KEYS ARE READ THE WAY THEY ARE (verified against strongSwan 5.9.13)
//   IKE keys. derive_ike_keys() splits the PRF+ output into SK_d|SK_ai|SK_ar|
//   SK_ei|SK_er|SK_pi|SK_pr. The encryption/integrity keys SK_ei/SK_er/SK_ai/
//   SK_ar are chunk_split("ammmmaa", ...) "move" slices that point INTO the
//   `keymat` buffer, which is chunk_clear()ed before the function returns — so
//   they are gone by onLeave and cannot be read from the struct or from the
//   out-arguments (there are none). They ARE, however, each dumped with
//   DBG4(DBG_IKE, "Sk_ei secret %B", &sk_ei) while still live. DBG4 expands to
//   an UNCONDITIONAL call of the exported libstrongswan `dbg` function pointer
//   (debug.h: `#define DBG4(group,fmt,...) dbg(group,4,fmt,##__VA_ARGS__)`);
//   only the formatting inside the logger is gated by the runtime log level.
//   So hooking `dbg` and matching the fmt pointer against the located key-dump
//   literals yields the live chunk_t* (4th argument) regardless of log level —
//   provided the build was compiled with DEBUG_LEVEL >= 4 (the stock default;
//   a reduced-debug build compiles the DBG4 sites and their literals out, and
//   IKE-key capture then degrades — see docs/limitation note).
//
//   ESP keys. Candidate 2 of the design: the CHILD_SA keys reach the kernel via
//   kernel_ipsec_t.add_sa(id, data) in the kernel-netlink plugin. That carries
//   SPI + protocol + src/dst in kernel_ipsec_sa_id_t and enc_alg/enc_key/
//   int_alg/int_key as plain struct fields in kernel_ipsec_add_sa_t — a stable,
//   documented ABI with NO by-value chunk_t arguments and NO dependence on the
//   debug level for the key READ (only the add_sa locator anchor is a DBG
//   literal, and a DBG1 anchor is included so locating survives DEBUG_LEVEL>=1).
//
// chunk_t is { u_char *ptr @0; size_t len @8 } (chunk.h). Struct offsets below
// were confirmed with offsetof on arm64; they are version-specific and labelled.

import { log, devlog } from "../../util/log.js";
import { sendKeyMaterial } from "../../shared/shared_structures.js";
import { toHexString } from "../../shared/shared_functions.js";
import {
    AnchorSpec, locateFunctionsByAnchors, agreedFunction, findLiteralOccurrences,
} from "../../shared/string_anchor_functions.js";
import { XREF_SCAN_CHUNK_BYTES, yieldToEventLoop } from "../../shared/arm64_xref.js";
import { findModuleExport } from "../../shared/module_exports.js";

// ---------------------------------------------------------------------------
// Pure data + helpers (unit-tested under Node without Frida)
// ---------------------------------------------------------------------------

/**
 * DBG4 literals UNIQUE to keymat_v2.c derive_ike_keys(). Two classes of literal
 * are deliberately excluded because they would make agreedFunction() see more
 * than one function and fail closed (verified against stock libcharon 5.9.13):
 *   - "Sk_d/Sk_pi/Sk_pr secret %B" also occur in derive_ike_keys_ppk();
 *   - "shared Diffie Hellman secret %B" also occurs in keymat_v1.c (IKEv1), so
 *     it resolves to two functions.
 * "SKEYSEED %B" (IKEv2-only) and the four "Sk_e{i,r}/Sk_a{i,r} secret %B" lines
 * are emitted only by keymat_v2 derive_ike_keys() and all co-locate there.
 */
export const IKE_FUNC_ANCHORS: AnchorSpec[] = [
    { text: "SKEYSEED %B" },
    { text: "Sk_ei secret %B" },
    { text: "Sk_er secret %B" },
    { text: "Sk_ai secret %B" },
    { text: "Sk_ar secret %B" },
];

/**
 * add_sa() in the kernel-netlink plugin. A DBG2 anchor (primary) plus two DBG1
 * anchors so the function is still located on a DEBUG_LEVEL>=1 build where DBG2
 * is compiled out. All three are unique to add_sa.
 */
export const ESP_FUNC_ANCHORS: AnchorSpec[] = [
    { text: "adding SAD entry with SPI %.8x and reqid {%u}%s" },
    { text: "unable to add SAD entry with SPI %.8x%s (%N)" },
    { text: "allocated SPI not found anymore, try to add SAD entry" },
];

/**
 * fmt literal -> canonical IKE key label. Matched against the `dbg` fmt pointer
 * at runtime. Only the four decryption-relevant keys are needed for Wireshark's
 * ikev2_decryption_table; SK_d/pi/pr are captured opportunistically when present.
 */
export const IKE_KEY_LITERALS: ReadonlyArray<readonly [string, string]> = [
    ["Sk_ei secret %B", "sk_ei"],
    ["Sk_er secret %B", "sk_er"],
    ["Sk_ai secret %B", "sk_ai"],
    ["Sk_ar secret %B", "sk_ar"],
    ["Sk_d secret %B", "sk_d"],
    ["Sk_pi secret %B", "sk_pi"],
    ["Sk_pr secret %B", "sk_pr"],
];

/** strongSwan transform_type_t values (transform.h). */
export const TRANSFORM_TYPE = { ENCRYPTION: 1, PRF: 2, INTEGRITY: 3 } as const;

/** kernel_ipsec protocol numbers (ipsec_types.h); ESP is the IANA protocol. */
export const PROTO_ESP = 50;

/** ike_sa_id_t vtable slots (ike_sa_id.h method order), 8 bytes each. */
export const IKE_SA_ID_SLOT = { GET_INITIATOR_SPI: 3, GET_RESPONDER_SPI: 4 } as const;
/** proposal_t vtable slot of get_algorithm (proposal.h method order). */
export const PROPOSAL_GET_ALGORITHM_SLOT = 2;

// private_ike_sa_id_t field offsets (strongSwan 5.9.13, arm64; vtable=88 + u8+pad).
const OFF_IKE_SPI_I = 96;
const OFF_IKE_SPI_R = 104;

// kernel_ipsec_sa_id_t / kernel_ipsec_add_sa_t field offsets (5.9.13, arm64).
const OFF_SAID_SPI = 16;     // uint32, network byte order
const OFF_SAID_PROTO = 20;   // uint8
const OFF_ADDSA_ENC_ALG = 40;
const OFF_ADDSA_ENC_KEY = 48; // chunk_t: ptr@48 len@56
const OFF_ADDSA_INT_ALG = 64;
const OFF_ADDSA_INT_KEY = 72; // chunk_t: ptr@72 len@80

const CHUNK_LEN_OFF = Process.pointerSize; // len follows ptr in chunk_t

/** Lowercase hex of `len` bytes at `ptr`, or null when unreadable / implausible. */
export function readChunkHex(ptr: NativePointer): string | null {
    try {
        if (ptr.isNull()) return null;
        const dataPtr = ptr.readPointer();
        const len = ptr.add(CHUNK_LEN_OFF).readULong().valueOf();
        if (dataPtr.isNull() || len <= 0 || len > 1024) return null;
        const bytes = dataPtr.readByteArray(len as number);
        return bytes ? toHexString(bytes) : null;
    } catch (e) {
        devlog(`[strongSwan] readChunkHex failed: ${e}`);
        return null;
    }
}

/** An IKE_SA key-derivation in progress on one thread. */
export interface IkeDerivation {
    spi_i: string;
    spi_r: string;
    enc_alg: number;
    enc_key_len_bits: number;
    int_alg: number;
    keys: { [label: string]: string };
}

/**
 * Build the ipsec_ike_keys message, or null when the minimum material for
 * Wireshark's ikev2_decryption_table (SPIs + SK_ei + SK_er) is missing.
 * Pure, so it is unit-testable without Frida.
 */
export function buildIkeMessage(ctx: IkeDerivation): { [k: string]: any } | null {
    if (!ctx.spi_i || !ctx.spi_r || !ctx.keys["sk_ei"] || !ctx.keys["sk_er"]) {
        return null;
    }
    return {
        contentType: "ipsec_ike_keys",
        ike_version: 2,
        spi_i: ctx.spi_i,
        spi_r: ctx.spi_r,
        enc_alg: ctx.enc_alg,
        enc_key_len_bits: ctx.enc_key_len_bits,
        int_alg: ctx.int_alg,
        keys: ctx.keys,
    };
}

/** Parts read from a single add_sa() call for one ESP SA direction. */
export interface EspSaParts {
    spi: string;      // 8 hex, on-wire (network) order
    proto: number;
    family: string;   // "IPv4" | "IPv6"
    enc_alg: number;
    int_alg: number;
    enc_key: string;  // hex
    int_key: string;  // hex ("" for AEAD / none)
}

/**
 * Build the ipsec_esp_keys message, or null for a non-ESP SA or one with no
 * encryption key. src/dst default to the "*" wildcards Wireshark's esp_sa
 * accepts (decryption is keyed by SPI). Pure.
 */
export function buildEspMessage(p: EspSaParts): { [k: string]: any } | null {
    if (p.proto !== PROTO_ESP || !p.spi || !p.enc_key) return null;
    return {
        contentType: "ipsec_esp_keys",
        spi: p.spi,
        src: "*",
        dst: "*",
        family: p.family,
        enc_alg: p.enc_alg,
        int_alg: p.int_alg,
        enc_key: p.enc_key,
        int_key: p.int_key,
    };
}

// ---------------------------------------------------------------------------
// Shared agent state (one JS context across the libcharon / libstrongswan /
// kernel-netlink module callbacks).
// ---------------------------------------------------------------------------

/** fmt literal address (as string) -> IKE key label. Filled from libcharon. */
const keyLiteralLabel = new Map<string, string>();
/** Per-thread in-progress IKE derivation (set in derive_ike_keys, filled by dbg). */
const ikeByThread = new Map<number, IkeDerivation>();

const installedOnModule = new Set<string>();

function alreadyDone(moduleName: string, tag: string): boolean {
    const key = `${tag}:${moduleName}`;
    if (installedOnModule.has(key)) return true;
    installedOnModule.add(key);
    return false;
}

const SCAN_OPTS = { chunkBytes: XREF_SCAN_CHUNK_BYTES, yieldFn: yieldToEventLoop };

// ---------------------------------------------------------------------------
// Frida: object introspection helpers
// ---------------------------------------------------------------------------

/** Call id->get_initiator/responder_spi via the vtable; read raw field as fallback. */
function readIkeSpis(id: NativePointer): { spi_i: string; spi_r: string } {
    // Raw field read gives the on-wire byte order directly (strongSwan stores
    // the 8 SPI bytes as received). Version-specific offsets (5.9.13, arm64).
    const spiHex = (off: number): string => {
        try {
            const b = id.add(off).readByteArray(8);
            return b ? toHexString(b) : "";
        } catch (_e) { return ""; }
    };
    return { spi_i: spiHex(OFF_IKE_SPI_I), spi_r: spiHex(OFF_IKE_SPI_R) };
}

/** proposal->get_algorithm(type) -> { alg, key_size_bits }, or null. */
function readProposalAlg(proposal: NativePointer, type: number): { alg: number; keyBits: number } | null {
    try {
        if (proposal.isNull()) return null;
        // proposal_t is an interface struct whose members ARE the method
        // pointers, so get_algorithm lives at proposal[slot].
        const fnPtr = proposal.add(PROPOSAL_GET_ALGORITHM_SLOT * Process.pointerSize).readPointer();
        if (fnPtr.isNull()) return null;
        const getAlgorithm = new NativeFunction(fnPtr, "bool",
            ["pointer", "int", "pointer", "pointer"]);
        const algOut = Memory.alloc(2);
        const sizeOut = Memory.alloc(2);
        algOut.writeU16(0);
        sizeOut.writeU16(0);
        const ok = getAlgorithm(proposal, type, algOut, sizeOut) as unknown as number;
        if (!ok) return null;
        return { alg: algOut.readU16(), keyBits: sizeOut.readU16() };
    } catch (e) {
        devlog(`[strongSwan] readProposalAlg(${type}) failed: ${e}`);
        return null;
    }
}

// ---------------------------------------------------------------------------
// Frida: hook installers
// ---------------------------------------------------------------------------

/**
 * libcharon: resolve the key-dump literals (for the dbg matcher) and hook
 * derive_ike_keys (located by its unique DBG4 anchors). Returns whether the
 * function was hooked.
 */
async function installCharonHooks(mod: Module): Promise<boolean> {
    // 1. Resolve the fmt literals the dbg hook matches against (log-level
    //    independent: the literals exist whenever DBG4 was compiled in).
    const texts = IKE_KEY_LITERALS.map(([text]) => text);
    const occ = await findLiteralOccurrences(mod, texts, SCAN_OPTS.chunkBytes, SCAN_OPTS.yieldFn);
    let resolved = 0;
    occ.forEach((addrs, i) => {
        if (addrs.length > 0) {
            // Map EVERY occurrence of the literal to the label: if the compiler
            // emitted more than one copy, derive_ike_keys may load a copy other
            // than the first, and the runtime fmt pointer must still match.
            for (const a of addrs) keyLiteralLabel.set(a.toString(), IKE_KEY_LITERALS[i][1]);
            resolved++;
        }
    });
    devlog(`[strongSwan] ${mod.name}: resolved ${resolved}/${texts.length} IKE key-dump literals`);

    // 2. Locate derive_ike_keys by the unique anchors and hook it.
    const perAnchor = await locateFunctionsByAnchors(mod, IKE_FUNC_ANCHORS, SCAN_OPTS);
    const fn = agreedFunction(perAnchor);
    if (fn === null) {
        // Per-anchor diagnostic: which literals located which function(s). This
        // distinguishes "literals compiled out" (all empty -> reduced
        // DEBUG_LEVEL) from "sites not bounded / disagree" (a locator issue).
        const diag = IKE_FUNC_ANCHORS.map((a, i) => {
            const r = perAnchor[i];
            const fns = r.functions.map((f) => "+0x" + f.start.sub(mod.base).toString(16)).join("|") || "-";
            return `"${a.text}"=>fns[${r.functions.length}]{${fns}} unbound=${r.unboundedSites.length}`;
        }).join("  ");
        log(`[-] ${mod.name}: could not locate derive_ike_keys (anchors did not agree; ` +
            `likely a reduced DEBUG_LEVEL build — IKE key capture unavailable)`);
        log(`[-] ${mod.name}: derive_ike_keys anchor diagnostic: ${diag}`);
        return false;
    }
    hookDeriveIkeKeys(mod, fn.start);
    log(`[*] ${mod.name}: hooked derive_ike_keys @ +0x${fn.start.sub(mod.base).toString(16)}`);
    // Capture the live SK_e{i,r}/SK_a{i,r} chunks at the charon bus logger. Those
    // keys are chunk_split "move" slices into `keymat`, freed before
    // derive_ike_keys returns, so they can't be read at onLeave; each is logged
    // with DBG4 while live. libcharon's DBG* macros do NOT go through the
    // libstrongswan `dbg` pointer — they call charon->bus->log() directly (see
    // hookCharonBusLog) — so the bus logger is the correct capture point.
    const ok = hookCharonBusLog(mod);
    log(`[*] ${mod.name}: charon bus logger hook ${ok ? "installed" : "unavailable"} for IKE key capture`);
    return true;
}

// Capture points already hooked, by address (dedupe + re-entry guard).
const hookedDispatchers = new Set<string>();

// daemon_t->bus and bus_t.log method offsets. Taken from the key-dump call-site
// disassembly of derive_ike_keys on stock libcharon 5.9.13 arm64:
//     ldr x0,[x19]            ; x0 = charon (daemon_t*)
//     ldr x0,[x0,#0x58]       ; x0 = charon->bus          (offset 88)
//     ldr x5,[x0,#0x30]       ; x5 = bus->log (the method) (offset 48)
//     blr x5                  ; log(bus, group, level, fmt, &chunk)
// Version-specific; a wrong value simply yields no bus-log hook (IKE capture off).
const OFF_DAEMON_BUS = 0x58;
const OFF_BUS_LOG_METHOD = 0x30;

/**
 * Hook charon->bus->log() and capture the IKE key-dump chunks.
 *
 * libcharon's debug macros expand to a direct `charon->bus->log(bus, group,
 * level, fmt, ...)` call, NOT to the libstrongswan `dbg` function pointer (which
 * only libstrongswan's own code uses). So the key dumps never reach `dbg`;
 * they reach the bus logger. Resolve that method from the exported `charon`
 * daemon object and hook it once (a function entry — safe to instrument). At the
 * logger, args are (this=bus, group, level, fmt, first vararg): fmt=args[3],
 * &chunk=args[4]. The fmt-pointer match keeps the hot path to one Map lookup.
 */
function hookCharonBusLog(mod: Module): boolean {
    const charonVar = findModuleExport(mod.name, "charon");
    if (charonVar === null || charonVar.isNull()) {
        devlog(`[strongSwan] ${mod.name}: no exported 'charon' daemon symbol`);
        return false;
    }
    let busLog: NativePointer;
    try {
        const daemon = charonVar.readPointer();
        if (daemon.isNull()) return false; // charon not initialised yet
        const bus = daemon.add(OFF_DAEMON_BUS).readPointer();
        if (bus.isNull()) return false;
        busLog = bus.add(OFF_BUS_LOG_METHOD).readPointer();
        if (busLog.isNull()) return false;
    } catch (e) {
        devlog(`[strongSwan] ${mod.name}: resolving charon->bus->log failed: ${e}`);
        return false;
    }
    if (hookedDispatchers.has(busLog.toString())) return true;
    try {
        Interceptor.attach(busLog, {
            onEnter(args: InvocationArguments) {
                try {
                    if (keyLiteralLabel.size === 0) return;
                    const ctx = ikeByThread.get(this.threadId);
                    if (!ctx) return; // only during a derive_ike_keys on this thread
                    // log(bus, debug_t group, level_t level, char *fmt, ...):
                    // fmt=args[3], first vararg (&chunk) = args[4].
                    const label = keyLiteralLabel.get(args[3].toString());
                    if (!label) return;
                    const hex = readChunkHex(args[4]);
                    if (hex) ctx.keys[label] = hex;
                } catch (_e) { /* never crash the daemon from a logging hook */ }
            },
        });
        hookedDispatchers.add(busLog.toString());
        devlog(`[strongSwan] hooked charon->bus->log @ ${busLog}`);
        return true;
    } catch (e) {
        devlog(`[strongSwan] could not hook charon->bus->log @ ${busLog}: ${e}`);
        return false;
    }
}

function hookDeriveIkeKeys(mod: Module, fnAddr: NativePointer): void {
    Interceptor.attach(fnAddr, {
        onEnter(args: InvocationArguments) {
            try {
                // derive_ike_keys(this, proposal, dh, chunk nonce_i, chunk nonce_r,
                //                 ike_sa_id_t *id, prf rekey_fn, chunk rekey_skd).
                // Frida arg indices (register-then-stack): arm64 id=args[7]
                // (x7, after the two by-value nonces in x3..x6); x64 id=args[5]
                // (nonce_r spilled to the stack, id back-filled r9).
                const proposal = args[1];
                const id = Process.arch === "x64" ? args[5] : args[7];
                const spis = readIkeSpis(id);
                const enc = readProposalAlg(proposal, TRANSFORM_TYPE.ENCRYPTION);
                const integ = readProposalAlg(proposal, TRANSFORM_TYPE.INTEGRITY);
                ikeByThread.set(this.threadId, {
                    spi_i: spis.spi_i,
                    spi_r: spis.spi_r,
                    enc_alg: enc?.alg ?? 0,
                    enc_key_len_bits: enc?.keyBits ?? 0,
                    int_alg: integ?.alg ?? 0,
                    keys: {},
                });
            } catch (e) {
                log(`[strongSwan] derive_ike_keys onEnter error: ${e}`);
            }
        },
        onLeave() {
            const ctx = ikeByThread.get(this.threadId);
            ikeByThread.delete(this.threadId);
            if (!ctx) return;
            const msg = buildIkeMessage(ctx);
            if (msg) {
                sendKeyMaterial(msg);
                log(`[*] IKE_SA keys extracted (SPIi=${ctx.spi_i} SPIr=${ctx.spi_r}, ` +
                    `${Object.keys(ctx.keys).length} keys)`);
            } else {
                devlog(`[strongSwan] derive_ike_keys returned but key set incomplete ` +
                    `(have: ${Object.keys(ctx.keys).join(",")})`);
            }
        },
    });
}


/**
 * kernel-netlink plugin: hook add_sa (located by its DBG anchors) and read the
 * ESP SA id + data structs. Emits one ipsec_esp_keys per direction.
 */
async function installKernelNetlinkHooks(mod: Module): Promise<boolean> {
    const perAnchor = await locateFunctionsByAnchors(mod, ESP_FUNC_ANCHORS, SCAN_OPTS);
    const fn = agreedFunction(perAnchor);
    if (fn === null) {
        log(`[-] ${mod.name}: could not locate add_sa (ESP key extraction unavailable)`);
        return false;
    }
    Interceptor.attach(fn.start, {
        onEnter(args: InvocationArguments) {
            try {
                const id = args[1];   // kernel_ipsec_sa_id_t *
                const data = args[2]; // kernel_ipsec_add_sa_t *
                if (id.isNull() || data.isNull()) return;
                const proto = id.add(OFF_SAID_PROTO).readU8();
                const spiBytes = id.add(OFF_SAID_SPI).readByteArray(4);
                const spi = spiBytes ? toHexString(spiBytes) : "";
                const enc_alg = data.add(OFF_ADDSA_ENC_ALG).readU16();
                const int_alg = data.add(OFF_ADDSA_INT_ALG).readU16();
                const enc_key = readChunkHex(data.add(OFF_ADDSA_ENC_KEY)) ?? "";
                const int_key = readChunkHex(data.add(OFF_ADDSA_INT_KEY)) ?? "";
                const msg = buildEspMessage({
                    spi, proto, family: "IPv4", enc_alg, int_alg, enc_key, int_key,
                });
                if (msg) {
                    sendKeyMaterial(msg);
                    log(`[*] ESP SA keys extracted (SPI=${spi}, enc_alg=${enc_alg}, int_alg=${int_alg})`);
                }
            } catch (e) {
                devlog(`[strongSwan] add_sa onEnter error: ${e}`);
            }
        },
    });
    log(`[*] ${mod.name}: hooked add_sa @ +0x${fn.start.sub(mod.base).toString(16)} for ESP key capture`);
    return true;
}

/** The strongSwan modules this extractor knows how to hook. */
function matchesStrongswanModule(moduleName: string): boolean {
    return /kernel-netlink\.so/.test(moduleName)
        || /libcharon\.so/.test(moduleName)
        || /libstrongswan\.so/.test(moduleName);
}

/**
 * Synchronous verdict + fire-and-forget scheduler. Returns true when
 * `moduleName` is a loaded strongSwan module this extractor targets (so the
 * loader reports library_detected), and kicks off the asynchronous hook
 * installation (the anchor scan yields to the event loop). Returns false for a
 * module that is not loaded or not one we handle, so the install verdict stays
 * accurate for the `-p`-only / nothing-resolvable case.
 */
export function scheduleStrongswanKeyHooks(moduleName: string): boolean {
    let present = false;
    try {
        present = Process.findModuleByName(moduleName) !== null;
    } catch (_e) {
        present = false;
    }
    if (!present || !matchesStrongswanModule(moduleName)) return false;
    installStrongswanKeyHooks(moduleName).catch((e) =>
        devlog(`[strongSwan] async key-hook install failed for ${moduleName}: ${e}`));
    return true;
}

/**
 * Install the strongSwan key hooks appropriate to `moduleName`. Called (async)
 * once per matched module (libcharon, libstrongswan, the kernel-netlink
 * plugin). Returns whether any hook was installed on this module.
 */
export async function installStrongswanKeyHooks(moduleName: string): Promise<boolean> {
    let mod: Module | null;
    try {
        mod = Process.findModuleByName(moduleName) ?? Process.getModuleByName(moduleName);
    } catch (_e) {
        mod = null;
    }
    if (mod === null) {
        devlog(`[strongSwan] module not found: ${moduleName}`);
        return false;
    }
    try {
        if (/kernel-netlink\.so/.test(moduleName)) {
            if (alreadyDone(moduleName, "esp")) return true;
            return await installKernelNetlinkHooks(mod);
        }
        if (/libcharon\.so/.test(moduleName)) {
            if (alreadyDone(moduleName, "ike")) return true;
            return await installCharonHooks(mod);
        }
        if (/libstrongswan\.so/.test(moduleName)) {
            if (alreadyDone(moduleName, "dbg")) return true;
            // IKE key capture is done in installCharonHooks (charon->bus->log);
            // nothing to hook in libstrongswan itself. Recognised either way.
            return true;
        }
    } catch (e) {
        devlog(`[strongSwan] installStrongswanKeyHooks(${moduleName}) threw: ${e}`);
        return false;
    }
    return false;
}

/** Test-only: reset the shared state between unit tests. */
export function _resetStrongswanState(): void {
    keyLiteralLabel.clear();
    ikeByThread.clear();
    installedOnModule.clear();
}
