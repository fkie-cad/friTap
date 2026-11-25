// Hook-installation readiness: tells the host when the agent's hooks are in.
//
// script.load() returns after the agent's TOP-LEVEL code, but some platform
// loaders (Android, Linux --quic-only) install their hooks in setTimeout(0)-
// yielded phases afterwards. A host that resumes a spawn-gated child as soon as
// load() returns lets the child's startup handshakes run before the keylog hooks
// exist. Each deferred install therefore registers itself here, and the entry
// sends ONE "agent_ready" message once every registered install has finished;
// the host waits (bounded) for it before resuming a suspended process.
//
// Single-threaded JS: the entry registers its callback at top level, before any
// setTimeout phase can finish, so the callback cannot be missed.

export const AGENT_READY_CONTENT_TYPE = "agent_ready";

let pendingInstalls = 0;
let settledCallback: (() => void) | null = null;

function fireIfSettled(): void {
    if (pendingInstalls !== 0 || settledCallback === null) return;
    const callback = settledCallback;
    settledCallback = null;
    callback();
}

/** Register a deferred install; call the returned function (idempotent) once it has finished. */
export function beginAsyncInstall(): () => void {
    pendingInstalls++;
    let finished = false;
    return () => {
        if (finished) return;
        finished = true;
        pendingInstalls--;
        fireIfSettled();
    };
}

/** Run *callback* once, as soon as no registered install is pending (immediately if none is). */
export function onInstallsSettled(callback: () => void): void {
    settledCallback = callback;
    fireIfSettled();
}

/** Tests only: forget all pending installs and the registered callback. */
export function resetInstallReadinessForTests(): void {
    pendingInstalls = 0;
    settledCallback = null;
}
