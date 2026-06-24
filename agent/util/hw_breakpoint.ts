import { devlog, log } from "./log.js";

/**
 * Hardware-breakpoint function-call watcher (EXPERIMENTAL).
 *
 * Part C of the PairIP work (fkie-cad/friTap#64). The motivating problem: a
 * normal `Interceptor.attach` (or any inline hook) on `android_dlopen_ext`
 * patches the linker's code bytes, which Google PairIP detects during its
 * startup integrity scan and answers with a SIGSEGV. We still want to learn
 * when a TLS library loads so we can hook *that library* directly (which PairIP
 * does not watch) — without modifying any code in the linker.
 *
 * Hardware breakpoints (Frida >= 16.5.0) use the ARM64 debug registers: NO
 * instruction bytes are changed, so a code-checksum / inline-hook detector does
 * not see them. We watch the *entry* of a function and re-arm via a one-shot
 * breakpoint on its return address (the captured `lr`), which lets the function
 * run normally between observations and avoids single-step bookkeeping.
 *
 * KNOWN LIMITATIONS (why this is gated behind an explicit experimental flag and
 * must be validated on-device — see friTap#64 experiment matrix E1-E4):
 *   - Debug registers are PER-THREAD. We arm every thread present at install
 *     time; a thread created *after* install is not covered, so a dlopen on a
 *     brand-new thread is missed.
 *   - Needs a kernel with ARM64 HW-breakpoint ptrace support and (typically)
 *     root frida-server. Some vendor kernels / SELinux-enforcing setups block it.
 *   - If PairIP ever inspects the debug registers (no public evidence it does),
 *     this would be detected too.
 *   - A misconfigured breakpoint can fault the target repeatedly. This is why
 *     it is opt-in and defaults OFF.
 */

// We use two of the ~6 ARM64 breakpoint slots: one for the function entry, one
// for the one-shot return-address breakpoint used to re-arm the entry cleanly.
const BP_ENTRY = 0;
const BP_RETURN = 1;

let _handlerInstalled = false;

function threadById(id: number): ThreadDetails | undefined {
    try {
        for (const t of Process.enumerateThreads()) {
            if (t.id === id) return t;
        }
    } catch (_) { /* enumeration can race teardown */ }
    return undefined;
}

/**
 * Observe every call to `funcAddr` without patching its code, invoking
 * `onEntry` once per call (best-effort, subject to the limitations above).
 *
 * @returns true if the watcher was armed on at least one thread.
 */
export function watchFunctionEntries(funcAddr: NativePointer, onEntry: () => void): boolean {
    if (!funcAddr || funcAddr.isNull()) return false;

    if (!_handlerInstalled) {
        _handlerInstalled = true;
        Process.setExceptionHandler((e: ExceptionDetails): boolean => {
            // Only debug-register events are ours; let everything else through
            // so we never swallow a real fault.
            if (e.type !== "breakpoint" && e.type !== "single-step") return false;

            const ctx = e.context as any; // arm64: pc + lr live here
            const tid = Process.getCurrentThreadId();
            const thread = threadById(tid);
            if (thread === undefined) return false;

            if (e.address.equals(funcAddr) || ctx.pc.equals(funcAddr)) {
                // Function entry. Fire the observer, then re-arm cleanly: drop
                // the entry breakpoint and arm a one-shot breakpoint on the
                // return address so the function body executes once, after
                // which we restore the entry breakpoint (see return branch).
                try { onEntry(); } catch (err) { devlog("[hw_bp] onEntry threw: " + err); }
                try {
                    const lr = ctx.lr as NativePointer;
                    thread.unsetHardwareBreakpoint(BP_ENTRY);
                    if (lr && !lr.isNull()) thread.setHardwareBreakpoint(BP_RETURN, lr);
                    else thread.setHardwareBreakpoint(BP_ENTRY, funcAddr); // no lr → just re-arm
                } catch (err) {
                    devlog("[hw_bp] re-arm (entry→return) failed: " + err);
                }
                return true; // resume; the breakpointed instruction now runs
            }

            // Return-address hit: the call has completed (library is loaded).
            // Drop the one-shot return breakpoint and restore the entry watch.
            try {
                thread.unsetHardwareBreakpoint(BP_RETURN);
                thread.setHardwareBreakpoint(BP_ENTRY, funcAddr);
            } catch (err) {
                devlog("[hw_bp] re-arm (return→entry) failed: " + err);
            }
            return true;
        });
    }

    let armed = 0;
    for (const t of Process.enumerateThreads()) {
        try {
            t.setHardwareBreakpoint(BP_ENTRY, funcAddr);
            armed++;
        } catch (err) {
            devlog(`[hw_bp] could not arm thread ${t.id}: ${err}`);
        }
    }
    if (armed === 0) {
        log("[!] Hardware-breakpoint watcher could not arm any thread (kernel/root/SELinux?). Stealth loader unavailable.");
        return false;
    }
    devlog(`[hw_bp] armed entry watch on ${armed} thread(s) @ ${funcAddr}`);
    return true;
}
