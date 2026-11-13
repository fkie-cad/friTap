// agent/tls/shared/go_plaintext.ts
//
// Plaintext hooks for Go crypto/tls that never use onLeave.
//
// Go functions must not get onLeave hooks: a goroutine that blocks inside the call
// (socket read/write) can resume on another OS thread — Frida's invocation stack is per
// thread, so the onLeave fires on the wrong invocation (or never) — and the return address
// Frida swaps in breaks Go's stack unwinder ("unknown caller pc") on GC / stack growth.
// Every hook here is therefore an onEnter-only probe whose registers already hold the
// exact plaintext, read via the Go ABIInternal layout (shared/go_abi.ts):
//
//   write: crypto/tls.(*Conn).writeRecordLocked(typ, data) — the per-record writer under
//          (*Conn).Write; `data` is exactly the record's plaintext (typ 23 only). See the
//          decision comment on installGoWriteRecordHook for why emitting at entry never
//          duplicates bytes.
//   read:  the copy inside crypto/tls.(*Conn).Read — `n, _ := c.input.Read(b)`, whose
//          bytes.(*Reader).Read is inlined down to a direct call of runtime.memmove(to=b,
//          from=decrypted record, n). A probe on that call instruction sees exactly the n
//          plaintext bytes this Read returns, after decryption and without any return hook.
//          (*halfConn).decrypt would need its results (onLeave), and c.input.Reset(data) is
//          inlined, so this call site is the one point where the delivered plaintext is an
//          argument. Requires the register ABI (Go >= 1.17 amd64 / >= 1.18 arm64).
//
// 386/arm (stack ABI): not installed. go_abi.ts decodes both probes' stack arguments, but on
// real Go 1.24 linux/386 and linux/arm binaries (Frida 17.24.3 gadget, qemu-user) these
// probes crashed the target ("fatal error: fault" / "unknown caller pc") — on 386 even with
// an empty onEnter on writeRecordLocked — while the writeKeyLog hook ran clean. Until that
// is understood on native 32-bit hardware, Go plaintext stays amd64/arm64-only.

import { sendDatalog } from "../../shared/shared_structures.js";
import { goMemmoveArgs, goWriteRecordArgs, isGoStackAbi, GO_TLS_RECORD_TYPE_APPLICATION_DATA } from "../../shared/go_abi.js";
import { devlog, devlog_error, log } from "../../util/log.js";
import { attachGoFunctionEntry } from "../../shared/go_attach.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { stampRecordLibrary } from "../../shared/record_message.js";
import { GO_SYMBOL_CONN_READ, GO_SYMBOL_MEMMOVE, GO_SYMBOL_WRITE_RECORD_LOCKED } from "./go_symbol_resolver.js";

/** Peer/session metadata of one Go record (no fd on a *tls.Conn), or null when unattributable. */
export type GoRecordMessageBuilder = (isRead: boolean) => { [key: string]: any } | null;

/** Upper bound of the (*Conn).Read scan; the function is ~0x200-0x400 bytes on amd64/arm64. */
const MAX_READ_SCAN_BYTES = 4096;

const CALL_MNEMONICS = new Set(["bl", "call"]);
const JUMP_MNEMONICS = new Set(["b", "jmp"]);

/** Direct branch target of a parsed call/jump ("#0x1234" on arm64, "0x1234" on x64), or null. */
function directTarget(instruction: Instruction): NativePointer | null {
    const operand = instruction.opStr.trim().replace(/^#/, "");
    return /^0x[0-9a-f]+$/i.test(operand) ? ptr(operand) : null;
}

/**
 * The address of the single direct call to `callee` inside the Go function at `fn`, or null
 * when there is none or more than one (ambiguous). The scan ends at the Go morestack
 * trailer — the jump back to the function's entry that closes every stack-checked Go
 * function — or after `maxBytes`.
 */
export function findGoCallSite(fn: NativePointer, callee: NativePointer,
                               maxBytes: number = MAX_READ_SCAN_BYTES): NativePointer | null {
    const end = fn.add(maxBytes);
    const sites: NativePointer[] = [];
    let cursor = fn;
    while (cursor.compare(end) < 0) {
        let instruction: Instruction;
        try {
            instruction = Instruction.parse(cursor);
        } catch (e) {
            break; // undecodable: stop rather than guess
        }
        const target = directTarget(instruction);
        if (target !== null && CALL_MNEMONICS.has(instruction.mnemonic) && target.equals(callee)) sites.push(cursor);
        if (target !== null && JUMP_MNEMONICS.has(instruction.mnemonic) && target.equals(fn)) break;
        cursor = instruction.next;
    }
    return sites.length === 1 ? sites[0] : null;
}

/** Whether the Go plaintext probes may be installed on `arch` (see the file comment: not 386/arm). */
export function goPlaintextSupported(arch: string = Process.arch): boolean {
    return !isGoStackAbi(arch);
}

/** Modules already warned that their Go plaintext is not captured. */
const modulesWarnedNoPlaintext = new Set<string>();

/**
 * Tells the user, once per module, that a 32-bit (stack-ABI) Go target yields keys only, so
 * a capture without plaintext is not mistaken for a hooking failure.
 */
export function warnGoPlaintextUnsupported(moduleName: string, arch: string = Process.arch): void {
    if (modulesWarnedNoPlaintext.has(moduleName)) return;
    modulesWarnedNoPlaintext.add(moduleName);
    log(`[!] ${moduleName}: Go TLS plaintext is not captured on 32-bit Go (${arch}); keys only`);
}

/**
 * onEnter-only hook of (*Conn).writeRecordLocked: emits each application-data record.
 * onEnter is exact here: writeRecordLocked is the per-record writer under (*Conn).Write (incl.
 * the TLS 1.0 1/n-1 split), `data` is exactly this call's plaintext. It returns n < len(data)
 * only together with an error, which (*Conn).Write latches in c.out.err (setErrorLocked: even a
 * timeout becomes a permanentError), so every later Write on the connection fails at once: no
 * retry can re-emit these bytes. At worst the unsent tail of a connection's final, failed write
 * is reported. Handshake/alert/CCS records (typ != 23) are skipped.
 */
export function installGoWriteRecordHook(address: NativePointer, buildMessage: GoRecordMessageBuilder): void {
    if (!goPlaintextSupported()) return;
    attachGoFunctionEntry(address, {
        onEnter() {
            const record = goWriteRecordArgs(this.context);
            if (record === null || record.recordType !== GO_TLS_RECORD_TYPE_APPLICATION_DATA) return;
            if (record.length <= 0) return;
            const message = buildMessage(false);
            if (message !== null) sendDatalog(message, record.data.readByteArray(record.length));
        },
    });
}

/**
 * Probe on the runtime.memmove call inside (*Conn).Read: emits the plaintext Read hands
 * to its caller. Returns false when the call site cannot be located unambiguously.
 */
export function installGoConnReadHook(connRead: NativePointer, memmove: NativePointer,
                                      buildMessage: GoRecordMessageBuilder): boolean {
    if (!goPlaintextSupported()) return false;
    const site = findGoCallSite(connRead, memmove);
    if (site === null) {
        devlog(`[gotls] (*Conn).Read @ ${connRead}: no unique runtime.memmove call; read hook skipped`);
        return false;
    }
    Interceptor.attach(site, {
        onEnter() {
            const copy = goMemmoveArgs(this.context);
            if (copy === null || copy.length <= 0) return;
            const message = buildMessage(true);
            if (message !== null) sendDatalog(message, copy.from.readByteArray(copy.length));
        },
    });
    devlog(`[gotls] (*Conn).Read plaintext probe at ${site} (+${site.sub(connRead)})`);
    return true;
}

/** Function labels of the Go plaintext records (direction is derived from "Read"). */
export const GO_READ_LABEL = "Go_Conn_Read";
export const GO_WRITE_LABEL = "Go_Conn_Write";

/**
 * Record metadata for Go plaintext: a *tls.Conn exposes no socket fd (on any OS — a Windows
 * SOCKET included), so records are attributable only with --enable_default_fd, as a
 * synthesized 5-tuple (getPortsAndAddresses(-1, ...)). Without it every record is dropped.
 * `moduleName` (the hooked Go binary) is stamped as the record's `library` label when given.
 */
export function goDefaultFdMessageBuilder(enableDefaultFd: boolean, moduleName?: string): GoRecordMessageBuilder {
    return (isRead) => {
        if (!enableDefaultFd) return null;
        const message: { [key: string]: any } | null = getPortsAndAddresses(-1, isRead, {}, enableDefaultFd);
        if (message === null) return null;
        message["ssl_session_id"] = "";
        message["function"] = isRead ? GO_READ_LABEL : GO_WRITE_LABEL;
        stampRecordLibrary(message, moduleName);
        return message;
    };
}

/**
 * Both onEnter-only plaintext probes of one Go module, shared by the modern definition and the
 * legacy executors: writes at (*Conn).writeRecordLocked, reads at the runtime.memmove call in
 * (*Conn).Read. `symbols` maps the canonical Go names (go_symbol_resolver.ts) to addresses; a
 * missing symbol (stripped binary) skips that direction. The caller gates on pcap_enabled.
 * Not installed on 32-bit (stack-ABI) Go — warned once instead.
 */
export function installGoPlaintextHooks(moduleName: string, symbols: { [symbol: string]: NativePointer },
                                        enableDefaultFd: boolean): void {
    if (!goPlaintextSupported()) {
        warnGoPlaintextUnsupported(moduleName);
        return;
    }
    const buildMessage = goDefaultFdMessageBuilder(enableDefaultFd, moduleName);
    const usable = (p: NativePointer | undefined): p is NativePointer => !!p && !p.isNull();
    try {
        const writeRecord = symbols[GO_SYMBOL_WRITE_RECORD_LOCKED];
        if (usable(writeRecord)) installGoWriteRecordHook(writeRecord, buildMessage);
        else devlog(`[gotls] ${GO_SYMBOL_WRITE_RECORD_LOCKED} unresolved in ${moduleName}; no write plaintext`);
    } catch (e) {
        devlog_error(`[gotls] write hook failed on ${moduleName}: ${e}`);
    }
    try {
        const connRead = symbols[GO_SYMBOL_CONN_READ];
        const memmove = symbols[GO_SYMBOL_MEMMOVE];
        if (usable(connRead) && usable(memmove)) installGoConnReadHook(connRead, memmove, buildMessage);
        else devlog(`[gotls] ${GO_SYMBOL_CONN_READ}/${GO_SYMBOL_MEMMOVE} unresolved in ${moduleName}; no read plaintext`);
    } catch (e) {
        devlog_error(`[gotls] read hook failed on ${moduleName}: ${e}`);
    }
}
