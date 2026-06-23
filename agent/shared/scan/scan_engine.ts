/**
 * scan_engine.ts — PUBLIC generic memory-region key-scan engine.
 *
 * Walks a CLI-selected region (--scan-keys-region {module | base,size | heap}),
 * applies the key_heuristics content tests inside scan_safety's guard rails, and
 * emits the top-ranked anonymous candidates as reveal-free "scan_candidate"
 * key material. A private protocol binding (full build only) can narrow the
 * region and add its own classifier via the scan_extension provider seam — but
 * the engine itself names no protocol and runs standalone in the public build.
 *
 * Shape modeled on agent/shared/strategies/memory_scan_strategy.ts: async,
 * chunked, and shutdown-aware. It reads the shutdown gate via
 * _isShuttingDownNow() (from util/log, which reads shared_structures) — NEVER
 * require("fritap_agent"), which would run the top-level install.
 */
import { _isShuttingDownNow, devlog, log } from "../../util/log.js";
import { toHexString } from "../../util/hex.js";
import { sendKeyMaterial, keylog_enabled } from "../shared_structures.js";
import {
    ScanRegionSpec, ScanCandidate, ScanProvider, collectScanProviders,
} from "./scan_extension.js";
import {
    OwnedRange, buildAgentOwnedRanges, isScanSafeRange,
    isRangeStillReadable, REVALIDATE_INTERVAL_BYTES,
} from "./scan_safety.js";
import { scoreCandidate, WINDOW_LEN } from "./key_heuristics.js";

// Tuning constants (bounded so a "heap" scan can't run unbounded or starve the
// event loop). All generic — no protocol assumptions.
const CHUNK_BYTES = 256 * 1024;       // memory read per chunk
const SCAN_STEP = 16;                 // window stride (key material is ≥8/16-aligned)
const SCHEDULE_LOOKAHEAD = 240;       // longest AES schedule the heuristics inspect
const MAX_CANDIDATES_PER_REGION = 64; // top-K kept per region while scanning
const MAX_EMIT = 64;                  // total candidates emitted
const EMIT_BYTES = 64;                // bytes carried per emitted candidate
const MAX_SCAN_BYTES = 64 * 1024 * 1024; // hard budget across the whole scan

/** Yield to the Frida event loop so gracefulDetach can run mid-scan. */
function yieldToLoop(): Promise<void> {
    return new Promise<void>((resolve) => setTimeout(resolve, 0));
}


/**
 * Parse the public --scan-keys-region value into region specs:
 *   "heap"        → every rw- range
 *   "0xADDR,SIZE" → one explicit region
 *   "<name>"      → every rw- range of the named module
 */
export function parseRegionValue(value: string): ScanRegionSpec[] {
    const v = (value || "").trim();
    if (!v) return [];
    if (v.toLowerCase() === "heap") return [{ kind: "heap", label: "heap" }];
    if (v.includes(",")) {
        const [baseStr, sizeStr] = v.split(",", 2).map((s) => s.trim());
        try {
            const base = ptr(baseStr);
            const size = sizeStr.toLowerCase().startsWith("0x")
                ? parseInt(sizeStr, 16) : parseInt(sizeStr, 10);
            if (size > 0) return [{ kind: "range", base, size, label: `${baseStr},${sizeStr}` }];
        } catch (e) {
            log(`[scan] could not parse region "${v}": ${e}`);
        }
        return [];
    }
    return [{ kind: "module", module: v, label: v }];
}

/** Resolve a region spec to the concrete RangeDetails the engine will walk. */
function resolveRanges(spec: ScanRegionSpec): RangeDetails[] {
    try {
        if (spec.kind === "heap") {
            return Process.enumerateRanges("rw-");
        }
        if (spec.kind === "module" && spec.module) {
            const mod = Process.findModuleByName(spec.module);
            if (!mod) { log(`[scan] module not found: ${spec.module}`); return []; }
            return mod.enumerateRanges("rw-");
        }
        if (spec.kind === "range" && spec.base && spec.size) {
            const containing = Process.findRangeByAddress(spec.base);
            return [{
                base: spec.base,
                size: spec.size,
                protection: containing ? containing.protection : "rw-",
                file: containing ? containing.file : undefined,
            } as RangeDetails];
        }
    } catch (e) {
        log(`[scan] resolveRanges(${spec.kind}) failed: ${e}`);
    }
    return [];
}

/** Keep only the highest-scoring, non-overlapping candidates. */
function rankAndDedup(cands: ScanCandidate[], limit: number): ScanCandidate[] {
    cands.sort((a, b) => b.score - a.score);
    const kept: ScanCandidate[] = [];
    for (const c of cands) {
        if (kept.length >= limit) break;
        const dup = kept.some((k) =>
            k.region === c.region && Math.abs(k.offset - c.offset) < WINDOW_LEN);
        if (!dup) kept.push(c);
    }
    return kept;
}

interface ScanBudget { scanned: number; truncated: boolean; }

/** Walk one safe range, accumulating candidates into `out` (bounded). */
async function scanRange(
    range: RangeDetails, regionLabel: string, out: ScanCandidate[], budget: ScanBudget,
): Promise<void> {
    let pos = 0;
    let sinceRevalidate = 0;
    while (pos < range.size) {
        if (_isShuttingDownNow()) return;
        if (budget.scanned >= MAX_SCAN_BYTES) { budget.truncated = true; return; }

        if (sinceRevalidate >= REVALIDATE_INTERVAL_BYTES) {
            if (!isRangeStillReadable(range.base.add(pos), 1)) return;
            sinceRevalidate = 0;
        }

        const chunkLen = Math.min(CHUNK_BYTES, range.size - pos);
        // Over-read so windows near the chunk tail still have AES-schedule lookahead.
        const readLen = Math.min(chunkLen + SCHEDULE_LOOKAHEAD, range.size - pos);
        let raw: ArrayBuffer | null = null;
        try {
            raw = range.base.add(pos).readByteArray(readLen);
        } catch (_e) {
            return; // unmapped mid-scan
        }
        if (raw === null) return;
        const buf = new Uint8Array(raw);

        for (let off = 0; off + WINDOW_LEN <= chunkLen; off += SCAN_STEP) {
            const cs = scoreCandidate(buf, off);
            // Keep every window that clears the entropy gate (scoreCandidate
            // returns score 0 below it). We deliberately do NOT require a
            // structural signal here: this is a GENERIC scanner whose whole job
            // is to surface plausible-width high-entropy windows so providers can
            // classify them — e.g. the Signal binding tags structureless 32-byte
            // keys (no AES schedule / x25519 clamp) via candidate.length === 32.
            // Gating those out would blind the protocol scanners. Discrimination
            // happens downstream: per-region score ranking (rankAndDedup, AES/
            // x25519 score far above bare entropy) plus a provider's own region
            // narrowing keep the bounded output meaningful.
            // (A prior `cs.signals.length < 2` "corroboration" guard here was
            // dead — secret_width fires on every plausible-width window, so it
            // never skipped anything — and making it real would break the above.)
            if (cs.score <= 0) continue;
            const len = Math.min(Math.max(cs.length, EMIT_BYTES), buf.length - off);
            const bytes: number[] = [];
            for (let i = 0; i < len; i++) bytes.push(buf[off + i]);
            out.push({
                region: regionLabel,
                offset: pos + off,
                length: cs.length,
                bytes,
                signals: cs.signals,
                score: cs.score,
            });
        }
        if (out.length > MAX_CANDIDATES_PER_REGION * 4) {
            const trimmed = rankAndDedup(out, MAX_CANDIDATES_PER_REGION);
            out.length = 0;
            out.push(...trimmed);
        }

        pos += chunkLen;
        budget.scanned += chunkLen;
        sinceRevalidate += chunkLen;
        await yieldToLoop();
    }
}

/**
 * Entry point. Runs only when the host passed --scan-keys-region (carried via
 * config_batch.extensions.scan_region) and/or a scan provider registered.
 * Async + fire-and-forget; emission is gated by keylog_enabled (so the host
 * must also pass -k).
 */
export async function maybeRunRegionScan(extensions: Record<string, any>): Promise<void> {
    const cliRegion: string | undefined = extensions && typeof extensions.scan_region === "string"
        ? extensions.scan_region : undefined;
    const providers = collectScanProviders();
    if (!cliRegion && providers.length === 0) return; // nothing requested

    if (!keylog_enabled) {
        log("[scan] --scan-keys-region set but keylog is disabled; pass -k to receive candidates.");
    }

    const specs: ScanRegionSpec[] = [];
    if (cliRegion) specs.push(...parseRegionValue(cliRegion));
    for (const p of providers) {
        try { specs.push(...p.selectRegions(extensions)); }
        catch (e) { devlog(`[scan] provider ${p.name} selectRegions failed: ${e}`); }
    }
    if (specs.length === 0) { log("[scan] no scannable regions resolved."); return; }

    log(`[scan] starting memory-region key scan over ${specs.length} region spec(s)`);
    const owned: OwnedRange[] = buildAgentOwnedRanges();
    const budget: ScanBudget = { scanned: 0, truncated: false };
    const all: ScanCandidate[] = [];

    try {
        for (const spec of specs) {
            if (_isShuttingDownNow()) break;
            const regionLabel = spec.label ?? spec.kind;
            const ranges = resolveRanges(spec);
            const regionCands: ScanCandidate[] = [];
            for (const range of ranges) {
                if (_isShuttingDownNow()) break;
                if (budget.scanned >= MAX_SCAN_BYTES) { budget.truncated = true; break; }
                const safety = isScanSafeRange(range, owned);
                if (!safety.safe) {
                    devlog(`[scan] skip ${range.base} (${range.size}B): ${safety.reason}`);
                    continue;
                }
                await scanRange(range, regionLabel, regionCands, budget);
            }
            all.push(...rankAndDedup(regionCands, MAX_CANDIDATES_PER_REGION));
        }
    } catch (e) {
        log(`[scan] aborted: ${e}`);
    }

    if (budget.truncated) {
        log(`[scan] budget reached (${MAX_SCAN_BYTES} bytes scanned); results are partial.`);
    }

    const ranked = rankAndDedup(all, MAX_EMIT);
    log(`[scan] scanned ${budget.scanned} bytes; emitting ${ranked.length} candidate(s).`);
    for (const c of ranked) {
        emitCandidate(c, extensions, providers);
    }
}

/** Emit one candidate: always the public scan_candidate, plus any private classifier. */
function emitCandidate(
    c: ScanCandidate, extensions: Record<string, any>, providers: ScanProvider[],
): void {
    sendKeyMaterial({
        contentType: "private_key_material",
        classifier: "scan_candidate",
        score: c.score,
        signals: c.signals,
        region: c.region,
        offset: c.offset,
        length: c.length,
        bytes: toHexString(c.bytes),
    });
    // Let any registered provider claim the candidate for its own (private)
    // confirmation path. Additive — never replaces the scan_candidate emission.
    for (const p of providers) {
        try {
            const claim = p.classify ? p.classify(c, extensions) : null;
            if (claim && claim.classifier) {
                sendKeyMaterial({
                    contentType: "private_key_material",
                    classifier: claim.classifier,
                    region: c.region,
                    offset: c.offset,
                    length: c.length,
                    bytes: toHexString(c.bytes),
                    ...(claim.fields ?? {}),
                });
            }
        } catch (e) {
            devlog(`[scan] provider ${p.name} classify failed: ${e}`);
        }
    }
}
