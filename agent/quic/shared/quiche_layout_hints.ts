// agent/quic/shared/quiche_layout_hints.ts
//
// Cross-run hints for the runtime-learned QUICHE layout (quiche_layout.ts,
// quiche_stream_id.ts), stored in the generic learned-offsets cache. A hint is
// only a candidate: quiche_records.ts validates it live before trusting it.

import {
    isLayoutRva, learnedLayout, rejectLearnedLayout, reportLearned,
} from "../../shared/learned_module_cache.js";
import type { CacheModule } from "../../shared/module_mapping.js";
import { Address, QuicheConnectionLayout, toAddress } from "./quiche_layout.js";

/** Cache item names (all offsets in bytes). */
export const QUICHE_HINT_NAMES = {
    /** QuicStream::session_ offset inside the stream. */
    streamSession: "quiche.layout.streamSession",
    /** QuicSession::connection_ offset inside the session. */
    sessionConnection: "quiche.layout.sessionConnection",
    /** (self, peer) QuicSocketAddress pair offset inside QuicConnection. */
    connectionAddresses: "quiche.layout.connectionAddresses",
    /** QuicConnection vptr minus the module base. */
    connectionVtableRva: "quiche.layout.connectionVtableRva",
    /** TlsClientHandshaker::session_ offset inside the handshaker. */
    handshakerSession: "quiche.layout.handshakerSession",
    /** QuicStream::id_ offset relative to session_'s offset (signed). */
    streamIdFromSession: "quiche.layout.streamIdFromSession",
} as const;

/** Independently validated units; "connection" covers the address offset plus the vtable. */
export type QuicheHintField = "streamSession" | "sessionConnection" | "connection" | "handshakerSession"
    | "streamIdFromSession";

/** Hint fields stored as one cache item each. */
type ScalarHintField = Exclude<QuicheHintField, "connection">;

export type QuicheLayoutHints = Partial<Record<ScalarHintField, number>> & { connection?: QuicheConnectionLayout };

const SCALAR_FIELDS: ScalarHintField[] = ["streamSession", "sessionConnection", "handshakerSession", "streamIdFromSession"];
/** Scalar fields that may legitimately be negative. */
const SIGNED_FIELDS: ReadonlySet<ScalarHintField> = new Set(["streamIdFromSession"]);
const CONNECTION_ITEMS = [QUICHE_HINT_NAMES.connectionAddresses, QUICHE_HINT_NAMES.connectionVtableRva];

function readConnectionHint(mod: CacheModule, isModuleAddress: (a: Address) => boolean): QuicheConnectionLayout | undefined {
    const addresses = learnedLayout(mod, QUICHE_HINT_NAMES.connectionAddresses);
    const rva = learnedLayout(mod, QUICHE_HINT_NAMES.connectionVtableRva);
    const vtable = rva === null ? null : toAddress(mod.base) + BigInt(rva);
    if (addresses !== null && addresses >= 0 && vtable !== null && isModuleAddress(vtable)) {
        return { connectionAddresses: addresses, connectionVtable: vtable };
    }
    forgetRejectedHint(mod, "connection");
    return undefined;
}

/**
 * The module's cached hints; a field is absent when not cached or out of range.
 * A discarded hint is rejected at once, so a value discovered later is reported.
 */
export function readQuicheLayoutHints(mod: CacheModule, isModuleAddress: (a: Address) => boolean): QuicheLayoutHints {
    const hints: QuicheLayoutHints = {};
    for (const field of SCALAR_FIELDS) {
        const value = learnedLayout(mod, QUICHE_HINT_NAMES[field]);
        if (value !== null && (SIGNED_FIELDS.has(field) || value >= 0)) hints[field] = value;
        else if (value !== null) forgetRejectedHint(mod, field);
    }
    const connection = readConnectionHint(mod, isModuleAddress);
    if (connection) hints.connection = connection;
    return hints;
}

/** One-line summary of the seeded hints for the debug log. */
export function describeHints(hints: QuicheLayoutHints): string {
    const hex = (v: number) => (v < 0 ? "-0x" : "0x") + Math.abs(v).toString(16);
    const parts: string[] = [];
    for (const field of SCALAR_FIELDS) {
        const value = hints[field];
        if (value !== undefined) parts.push(`${field}=${hex(value)}`);
    }
    if (hints.connection) {
        parts.push(`connectionAddresses=${hex(hints.connection.connectionAddresses)}`,
                   `connectionVtable=0x${hints.connection.connectionVtable.toString(16)}`);
    }
    return parts.join(", ");
}

/** Lets a corrected value of `field` be reported after its hint failed validation. */
export function forgetRejectedHint(mod: CacheModule, field: QuicheHintField): void {
    const names = field === "connection" ? CONNECTION_ITEMS : [QUICHE_HINT_NAMES[field]];
    for (const name of names) rejectLearnedLayout(mod, name);
}

/** Report live-discovered values; the cache drops values that came from it. */
export function reportQuicheLayout(mod: CacheModule, values: QuicheLayoutHints): void {
    const layout: Record<string, number> = {};
    for (const field of SCALAR_FIELDS) {
        const value = values[field];
        if (value !== undefined) layout[QUICHE_HINT_NAMES[field]] = value;
    }
    if (values.connection) {
        layout[QUICHE_HINT_NAMES.connectionAddresses] = values.connection.connectionAddresses;
        // Only a vtable at/after the module base has a stable RVA (not size-bounded: see isLayoutRva).
        const rva = values.connection.connectionVtable - toAddress(mod.base);
        if (rva > 0n && isLayoutRva(Number(rva))) layout[QUICHE_HINT_NAMES.connectionVtableRva] = Number(rva);
    }
    if (Object.keys(layout).length > 0) reportLearned(mod, { layout });
}
