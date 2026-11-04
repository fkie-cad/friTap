// agent/ssh/shared/openssh_functions.ts
//
// Where the OpenSSH functions the SSH hooks attach to live in one module.
//
// WHY: the stock `ssh` / `sshd` of Debian and Ubuntu is stripped, so none of the hooked
// functions is exported and findModuleExport() finds nothing. Every one of them logs,
// though, and OpenSSH's log macros (debug*/error*/logit/... and their *_f forms) pass
// `__func__`, so the function's own name is a literal only its code loads; unique log
// messages are second anchors. The exported symbol stays the first choice; the anchors
// (agent/shared/string_anchor_functions.ts) are the fallback for stripped builds.
//
// Verified against the stripped packages and their debug symbols (dbgsym / ddeb) of
// Debian 12 (9.2p1), Debian 13 (10.0p1), Ubuntu 22.04 (8.9p1) and Ubuntu 24.04 (9.6p1),
// arm64 and amd64. Ubuntu builds with LTO, which inlines two hooked functions into their
// only caller (ssh_packet_read_poll2 -> ssh_packet_read_poll_seqnr, ssh_packet_send2 ->
// sshpkt_send): their anchors then agree on the caller, which `notIn` rejects, and the
// hooks use the caller instead (same signature, see ssh_packet_hooks.ts).
//
// The log MESSAGES are the anchors that carry arm64: GCC addresses the `__func__` arrays
// there through a section anchor (`adrp+add` of a block base, then `add #offset`), a
// shape the native xref scan does not follow, so on arm64 only the messages are seen.
// Every function below therefore has at least one message anchor, and every `notIn`
// lists a message of the caller as well as its `__func__`.
//
// Not anchored: cipher_init logs nothing. Stripped builds get the per-direction keys from
// the ssh_set_newkeys sshenc walk instead (ssh_linux.ts); the shared secret, which is
// what Wireshark needs, comes from kex_derive_keys either way.

import { devlog } from "../../util/log.js";
import { findModuleExport } from "../../shared/module_exports.js";
import { findAnchorString } from "../../shared/arm64_xref.js";
import { activeRecordProtocol, runHookExecutor } from "../../shared/record_protocol.js";
import {
    AnchorFunctions, AnchorSpec, agreedFunction, locateFunctionsByAnchors,
} from "../../shared/string_anchor_functions.js";

/** The not-necessarily-exported OpenSSH functions the SSH hooks and guards use. */
export type OpenSshFunction =
    | "kex_derive_keys" | "kex_send_kexinit" | "kex_input_kexinit" | "ssh_set_newkeys"
    | "ssh_packet_read_poll2" | "ssh_packet_read_poll_seqnr" | "ssh_packet_send2_wrapped"
    | "closefrom";

export interface FunctionAnchors {
    /** Literals only this function loads: its `__func__` first, then messages it logs. */
    anchors: string[];
    /** Literals of the caller it can be inlined into: the located function must load none. */
    notIn?: string[];
}

export const OPENSSH_FUNCTION_ANCHORS: Readonly<Record<OpenSshFunction, FunctionAnchors>> = {
    kex_derive_keys: { anchors: ["kex_derive_keys", "already have session ID at kex", "no session ID in rekex"] },
    kex_send_kexinit: { anchors: ["kex_send_kexinit", "SSH2_MSG_KEXINIT sent"] },
    kex_input_kexinit: { anchors: ["kex_input_kexinit", "SSH2_MSG_KEXINIT received"] },
    ssh_set_newkeys: { anchors: ["ssh_set_newkeys", "rekey %s after %llu blocks"] },
    ssh_packet_read_poll2: {
        anchors: ["ssh_packet_read_poll2", "receive packet: type %u", "incoming seqnr wraps around",
            "resetting read seqnr %u"],
        notIn: ["ssh_packet_read_poll_seqnr", "Received SSH2_MSG_IGNORE"],
    },
    ssh_packet_read_poll_seqnr: { anchors: ["ssh_packet_read_poll_seqnr", "Received SSH2_MSG_IGNORE"] },
    ssh_packet_send2_wrapped: {
        anchors: ["ssh_packet_send2_wrapped", "send packet: type %u", "outgoing seqnr wraps around",
            "resetting send seqnr %u"],
        notIn: ["ssh_packet_send2", "enqueue packet: %u", "dequeue packet: %u"],
    },
    // openbsd-compat closefrom(): the stock binaries carry their own copy (not libc's).
    closefrom: { anchors: ["/proc/%ld/fd"] },
};

/** Literal whose presence marks a module as OpenSSH, checked before the full anchor pass. */
const OPENSSH_MARKER = "kex_derive_keys";

/** Where each table function's anchors and exclusions sit in one batched spec list. */
export interface AnchorPlan {
    specs: AnchorSpec[];
    slots: { name: OpenSshFunction; anchors: number[]; notIn: number[] }[];
}

/** One batched spec list for `names` (shared literals are listed once). */
export function planAnchors(names: OpenSshFunction[], table = OPENSSH_FUNCTION_ANCHORS): AnchorPlan {
    const specs: AnchorSpec[] = [];
    const indexOf = (text: string): number => {
        const known = specs.findIndex((s) => s.text === text);
        return known >= 0 ? known : specs.push({ text }) - 1;
    };
    const slots = names.map((name) => ({
        name,
        anchors: table[name].anchors.map(indexOf),
        notIn: (table[name].notIn ?? []).map(indexOf),
    }));
    return { specs, slots };
}

/**
 * Each function's start from the batched results (agreedFunction per function). Two
 * functions that resolve to the same start are both dropped: one of them was inlined
 * into the other, and neither can be hooked as itself.
 */
export function pickFunctions(plan: AnchorPlan, results: AnchorFunctions[]): Map<OpenSshFunction, NativePointer> {
    const picked = new Map<OpenSshFunction, NativePointer>();
    for (const slot of plan.slots) {
        const fn = agreedFunction(slot.anchors.map((i) => results[i]), slot.notIn.map((i) => results[i]));
        if (fn !== null) picked.set(slot.name, fn.start);
    }
    const starts = [...picked.values()].map(String);
    for (const [name, start] of [...picked]) {
        if (starts.filter((s) => s === start.toString()).length > 1) picked.delete(name);
    }
    return picked;
}

const ALL_FUNCTIONS = Object.keys(OPENSSH_FUNCTION_ANCHORS) as OpenSshFunction[];
/** moduleName@base -> functions located by anchors (empty: resolved, nothing found). */
const anchored = new Map<string, Map<OpenSshFunction, NativePointer>>();

function moduleOf(moduleName: string): Module | null {
    try {
        return (Process as any).findModuleByName?.(moduleName) ?? null;
    } catch (_e) {
        return null;
    }
}

function keyOf(mod: Module): string {
    return `${mod.name}@${mod.base}`;
}

/** The hook address of `name` in `moduleName`: its export, else its anchor-located start. */
export function openSshFunction(moduleName: string, name: OpenSshFunction): NativePointer | null {
    const exported = findModuleExport(moduleName, name);
    if (exported !== null) return exported;
    const mod = moduleOf(moduleName);
    return mod ? anchored.get(keyOf(mod))?.get(name) ?? null : null;
}

/** Whether anchors located any OpenSSH function in `moduleName` (it is a stripped OpenSSH). */
export function locatedByAnchors(moduleName: string): boolean {
    const mod = moduleOf(moduleName);
    return mod !== null && (anchored.get(keyOf(mod))?.size ?? 0) > 0;
}

/**
 * Whether `moduleName` needs the (async) anchor pass before its hooks are installed:
 * an ELF module not yet resolved, missing some table export, that contains OpenSSH's
 * marker literal. Cheap and synchronous; never throws.
 */
export function needsAnchorResolution(moduleName: string): boolean {
    try {
        if (Process.platform !== "linux") return false;
        const mod = moduleOf(moduleName);
        if (mod === null || anchored.has(keyOf(mod))) return false;
        if (ALL_FUNCTIONS.every((name) => findModuleExport(moduleName, name) !== null)) return false;
        return findAnchorString(mod, OPENSSH_MARKER + "\u0000") !== null;
    } catch (_e) {
        return false;
    }
}

/** Immediate yield: an `ssh` binary is small, and spawned targets must be hooked before resume. */
const noYield = (): Promise<void> => Promise.resolve();

/** Locate the not-exported table functions of `moduleName` by their anchors, once. Never throws. */
export async function resolveOpenSshFunctions(moduleName: string): Promise<void> {
    const mod = moduleOf(moduleName);
    if (mod === null || anchored.has(keyOf(mod))) return;
    const missing = ALL_FUNCTIONS.filter((name) => findModuleExport(moduleName, name) === null);
    const plan = planAnchors(missing);
    let found = new Map<OpenSshFunction, NativePointer>();
    try {
        found = pickFunctions(plan, await locateFunctionsByAnchors(mod, plan.specs, { yieldFn: noYield }));
    } catch (e) {
        devlog(`[SSH] anchor locator failed in ${moduleName}: ${e}`);
    }
    anchored.set(keyOf(mod), found);
    const where = [...found].map(([n, p]) => `${n}@+0x${p.sub(mod.base).toString(16)}`);
    const lost = missing.filter((n) => !found.has(n));
    devlog(`[SSH] ${moduleName}: located by string anchors: ${where.join(", ") || "none"}` +
        (lost.length > 0 ? `; not located: ${lost.join(", ")}` : ""));
}

/**
 * Run `install` once the module's functions are resolved: right away when nothing is
 * missing, else after the anchor pass, re-bound to the record protocol active now (the
 * loader binds it only while the executor runs synchronously; record_protocol.ts).
 */
export function withOpenSshFunctions<T>(moduleName: string, install: () => T): T | Promise<Awaited<T>> {
    if (!needsAnchorResolution(moduleName)) return install();
    const protocol = activeRecordProtocol();
    return resolveOpenSshFunctions(moduleName)
        .then(() => (protocol === undefined ? install() : runHookExecutor(protocol, install)) as Awaited<T>);
}
