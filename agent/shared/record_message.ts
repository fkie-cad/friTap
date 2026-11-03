// agent/shared/record_message.ts
//
// The datalog message for one plaintext TLS record: peer addressing plus the SSL
// session fields. Shared by every SSL_read/SSL_write(_ex) hook (modern executors,
// the SSL_*_ex extra hooks and the legacy class-based OpenSSL/BoringSSL hooks).

import { getPortsAndAddresses } from "./shared_functions.js";

export type RecordFields = { [field: string]: string | number };

export interface RecordContext {
    /** Socket fd of the record's connection (SSL_get_fd, or recovered via the fd tracker). */
    fd: number;
    isRead: boolean;
    /** Hooked function name, reported as message.function. */
    functionName: string;
    methodAddresses: { [fn: string]: NativePointer };
    enableDefaultFd: boolean;
    /** Replaces getPortsAndAddresses for libraries with their own address logic. */
    resolvePeer?: () => RecordFields | null;
}

/**
 * Peer/session metadata for one plaintext record, or null when it cannot be
 * attributed (no usable fd and no --enable_default_fd, or a non-IP socket).
 * `sessionFields` is only evaluated for attributable records.
 */
export function buildRecordMessage(ctx: RecordContext, sessionFields: () => RecordFields): any | null {
    const message = ctx.resolvePeer
        ? ctx.resolvePeer()
        : getPortsAndAddresses(ctx.fd, ctx.isRead, ctx.methodAddresses, ctx.enableDefaultFd);
    if (message === null) return null;
    Object.assign(message, sessionFields());
    message["function"] = ctx.functionName;
    return message;
}
