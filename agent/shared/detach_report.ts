/**
 * DetachReport (contract version 1): the result of `releaseAgentHooks()`,
 * returned to the host by the synchronous `gracefulDetach` RPC.
 *
 * Every send is dropped once the shutdown flag is set, so before this report
 * existed the teardown was silent: a failed revert or a skipped socket left no
 * trace. The report carries per-step timing, outcome, an optional small summary
 * and the log()/devlog()/devlog_* lines emitted while teardown ran, and it travels in
 * the RPC reply, independent of the (already stopping) message channel.
 *
 * LEAF MODULE: it imports nothing. agent/util/log.ts imports the capture sink
 * from here, and log.ts is imported by almost every module during init; any
 * import added here could close a cycle that frida-compile resolves to
 * `undefined` at load time.
 */

export const DETACH_REPORT_VERSION = 1;

/** Longest kept error message, log line or summary string. */
export const DETACH_TEXT_LIMIT = 300;
/** Captured log lines kept per report; later ones only bump dropped_logs. */
export const DETACH_LOG_LIMIT = 100;
/** Summary keys kept per step (a summary is a handful of counters). */
const SUMMARY_KEY_LIMIT = 32;

export type DetachSummaryValue = number | string | boolean;
export type DetachSummary = { [key: string]: DetachSummaryValue };
/**
 * "info" = log() and devlog_info(), "debug" = devlog() and devlog_debug(),
 * "warn" = devlog_warn(), "error" = devlog_error(). Same names as the Level of
 * the leveled devlog_* helpers in agent/util/log.ts.
 */
export type DetachLogLevel = "info" | "debug" | "warn" | "error";

export interface DetachStep {
    name: string;
    ok: boolean;
    ms: number;
    summary?: DetachSummary;
    error?: string;
}

export interface DetachLogEntry {
    level: DetachLogLevel;
    msg: string;
}

export interface DetachReport {
    version: 1;
    repeat: boolean;
    total_ms: number;
    steps: DetachStep[];
    logs: DetachLogEntry[];
    dropped_logs: number;
}

function clip(text: string): string {
    return text.length > DETACH_TEXT_LIMIT ? text.slice(0, DETACH_TEXT_LIMIT) : text;
}

function describeError(e: unknown): string {
    try {
        return clip(String(e));
    } catch (_e) {
        return "<unprintable error>";
    }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}

function sanitizeSummaryValue(value: unknown): DetachSummaryValue | undefined {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
    if (typeof value === "string") return clip(value);
    return undefined;
}

/**
 * Keep only a plain object's number/string/boolean fields (no NativePointers,
 * nested objects or non-finite numbers), so the report stays small and
 * JSON-serialisable. Returns undefined when nothing usable is left.
 */
export function sanitizeDetachSummary(value: unknown): DetachSummary | undefined {
    if (!isPlainObject(value)) return undefined;
    const summary: DetachSummary = {};
    let kept = 0;
    for (const key of Object.keys(value)) {
        if (kept >= SUMMARY_KEY_LIMIT) break;
        const clean = sanitizeSummaryValue(value[key]);
        if (clean === undefined) continue;
        summary[clip(key)] = clean;
        kept++;
    }
    return kept > 0 ? summary : undefined;
}

/** Collects the steps and captured logs of one teardown run. Never throws. */
export class DetachReportBuilder {
    private readonly startedAt = Date.now();
    private readonly steps: DetachStep[] = [];
    private readonly logs: DetachLogEntry[] = [];
    private droppedLogs = 0;

    constructor(private readonly progress?: (phase: "started" | "finished", name: string) => void) {}

    /** Run `fn` as a named step: timed, isolated, its return value kept as the summary. */
    step(name: string, fn: () => unknown): void {
        this.progress?.("started", name);
        const started = Date.now();
        const entry: DetachStep = { name, ok: true, ms: 0 };
        try {
            const summary = sanitizeDetachSummary(fn());
            if (summary) entry.summary = summary;
        } catch (e) {
            entry.ok = false;
            entry.error = describeError(e);
        }
        entry.ms = Date.now() - started;
        this.steps.push(entry);
        this.progress?.("finished", name);
    }

    addLog(level: DetachLogLevel, msg: unknown): void {
        if (this.logs.length >= DETACH_LOG_LIMIT) {
            this.droppedLogs++;
            return;
        }
        this.logs.push({ level, msg: clip(typeof msg === "string" ? msg : describeError(msg)) });
    }

    finish(): DetachReport {
        return {
            version: DETACH_REPORT_VERSION,
            repeat: false,
            total_ms: Date.now() - this.startedAt,
            steps: this.steps.slice(),
            logs: this.logs.slice(),
            dropped_logs: this.droppedLogs,
        };
    }
}

/** The report of a teardown that already ran (e.g. `dispose` after `gracefulDetach`). */
export function repeatDetachReport(): DetachReport {
    return { version: DETACH_REPORT_VERSION, repeat: true, steps: [], logs: [], dropped_logs: 0, total_ms: 0 };
}

// ---------------------------------------------------------------------------
// Teardown log capture scope.
//
// While a scope is active, every log variant of agent/util/log.ts (log, devlog
// and the leveled devlog_* helpers) hands its line to the active report instead
// of sending it (sends are dropped once the shutdown flag is set).
// Safe without locking: releaseAgentHooks holds the script's JS lock for its
// whole duration, so no other callback can log into the scope concurrently.
// ---------------------------------------------------------------------------

let activeCapture: DetachReportBuilder | null = null;

export function beginTeardownCapture(report: DetachReportBuilder): void {
    activeCapture = report;
}

export function endTeardownCapture(): void {
    activeCapture = null;
}

/** Run `fn` with the capture scope active, ending it even when `fn` throws. */
export function withTeardownCapture<T>(report: DetachReportBuilder, fn: () => T): T {
    beginTeardownCapture(report);
    try {
        return fn();
    } finally {
        endTeardownCapture();
    }
}

/**
 * Log sink used by agent/util/log.ts. Returns true when the line was taken by
 * an active capture scope (the caller must then not send it), false otherwise.
 */
export function captureTeardownLog(level: DetachLogLevel, msg: unknown): boolean {
    if (activeCapture === null) return false;
    try {
        activeCapture.addLog(level, msg);
    } catch (_e) {
        /* a log call must never throw */
    }
    return true;
}
