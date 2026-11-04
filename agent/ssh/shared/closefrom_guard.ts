// agent/ssh/shared/closefrom_guard.ts
//
// Keep Frida's own file descriptors open across the target's closefrom().
//
// WHY: the OpenSSH client calls closefrom(STDERR_FILENO + 1) at the top of main(). In spawn
// mode the agent is injected before that, so closefrom() also closes the agent's channel to
// friTap: the hooks keep running but every send() is lost (no keylog, no PCAP — GLib then
// logs "_g_dbus_worker_do_read_cb ... malformed"). We replace closefrom() with a version
// that skips the descriptors that were already open when the hooks were installed (the
// agent's, in spawn mode) and otherwise behaves like the original.

import { devlog } from "../../util/log.js";
import { openSshFunction } from "./openssh_functions.js";

/** fcntl(2) F_GETFD: succeeds exactly when the descriptor is open. */
const F_GETFD = 1;
/** Highest descriptor inspected when snapshotting (agents open only a handful, low ones). */
const SNAPSHOT_MAX_FD = 1024;

/** What a guarded closefrom(lowfd) does: close() each listed fd, then the original from `originalFrom`. */
export interface ClosefromPlan {
    closeEach: number[];
    originalFrom: number;
}

/**
 * Plan closefrom(lowfd) so that no fd in `preserved` is closed. Every other fd >= lowfd is
 * still closed: the ones below the highest preserved fd one by one, the rest by the
 * original closefrom().
 */
export function planClosefrom(lowfd: number, preserved: ReadonlySet<number>): ClosefromPlan {
    const kept = [...preserved].filter((fd) => fd >= lowfd);
    if (kept.length === 0) return { closeEach: [], originalFrom: lowfd };
    const highest = Math.max(...kept);
    const closeEach: number[] = [];
    for (let fd = Math.max(lowfd, 0); fd < highest; fd++) {
        if (!preserved.has(fd)) closeEach.push(fd);
    }
    return { closeEach, originalFrom: highest + 1 };
}

const guardedTargets = new Set<string>();

/**
 * The closefrom() addresses still to guard: non-null, not guarded yet, each once. The
 * module's own copy and the global lookup are usually the SAME function (an executable's
 * closefrom interposes libc's, so the global lookup finds it first); replacing it twice
 * throws "already replaced this function".
 */
export function closefromTargetsToGuard(candidates: (NativePointer | null)[], guarded: ReadonlySet<string>): NativePointer[] {
    const seen = new Set<string>(guarded);
    const targets: NativePointer[] = [];
    for (const t of candidates) {
        if (t === null || seen.has(t.toString())) continue;
        seen.add(t.toString());
        targets.push(t);
    }
    return targets;
}

function libcFunction(name: string, ret: NativeFunctionReturnType, args: NativeFunctionArgumentType[]): any {
    const addr = Module.findGlobalExportByName(name);
    return addr ? new NativeFunction(addr, ret, args) : null;
}

/** The descriptors >= 3 open right now (the agent's own, when called before the target's main). */
function snapshotOpenFds(fcntl: any): Set<number> {
    const open = new Set<number>();
    for (let fd = 3; fd < SNAPSHOT_MAX_FD; fd++) {
        if ((fcntl(fd, F_GETFD) as number) !== -1) open.add(fd);
    }
    return open;
}

function guard(target: NativePointer, preserved: Set<number>, ownerPid: number, getpid: any, close: any): void {
    const original = new NativeFunction(target, "void", ["int"]);
    Interceptor.replace(target, new NativeCallback((lowfd: number) => {
        // A forked child has its own agent channel (or none): plain closefrom there.
        if ((getpid() as number) !== ownerPid) {
            original(lowfd);
            return;
        }
        const plan = planClosefrom(lowfd, preserved);
        for (const fd of plan.closeEach) close(fd);
        original(plan.originalFrom);
    }, "void", ["int"]));
}

/**
 * Guard closefrom() — the module's own (OpenSSH's openbsd-compat copy: exported, or located
 * by its string anchor in the stripped Debian/Ubuntu builds, which all carry one) and
 * libc's — against closing the descriptors open now. Linux only; call while installing
 * hooks, i.e. before the target's main() in spawn mode. Returns whether a guard is active.
 */
export function guardAgentFdsAgainstClosefrom(moduleName: string): boolean {
    if (Process.platform !== "linux") return false;
    try {
        const fcntl = libcFunction("fcntl", "int", ["int", "int"]);
        const close = libcFunction("close", "int", ["int"]);
        const getpid = libcFunction("getpid", "int", []);
        if (!fcntl || !close || !getpid) return false;
        const targets = closefromTargetsToGuard(
            [openSshFunction(moduleName, "closefrom"), Module.findGlobalExportByName("closefrom")], guardedTargets);
        if (targets.length === 0) return guardedTargets.size > 0;
        const preserved = snapshotOpenFds(fcntl);
        const ownerPid = getpid() as number;
        for (const target of targets) {
            guard(target, preserved, ownerPid, getpid, close);
            guardedTargets.add(target.toString());
        }
        devlog(`[SSH] closefrom() guarded at ${targets.join(", ")}; preserving fds ${[...preserved].join(",")}`);
        return true;
    } catch (e) {
        devlog(`[SSH] closefrom guard failed: ${e}`);
        return false;
    }
}
