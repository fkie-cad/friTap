// agent/shared/keylog_guards.ts
//
// Fail-closed guards shared by the keylog-writer locators and their hooks
// (BoringSSL tier 4, NSS tier 1, Fizz): the three-state decode verdict that
// keeps "could not read" apart from "does not decode", and the label
// self-check that removes a hook whose calls stop carrying known labels.
// Pure: no Frida APIs, unit-tested under Node.

/** A decode that could not read every byte it needed: no verdict. */
export const DECODE_UNREADABLE: unique symbol = Symbol("decode-unreadable");
export type Decoded<T> = T | null | typeof DECODE_UNREADABLE;
/** true: decodes; false: read in full and does not decode; null: unknown (unreadable). */
export type DecodeVerdict = boolean | null;

export function isDecoded<T>(d: Decoded<T>): d is T {
    return d !== null && d !== DECODE_UNREADABLE;
}

/** `decoded`, unless it is null and the read behind it was short: then the miss proves nothing. */
export function unreadableIfShort<T>(decoded: T | null, readInFull: boolean): Decoded<T> {
    return decoded === null && !readInFull ? DECODE_UNREADABLE : decoded;
}

export type LabelVerdict = "emit" | "skip" | "detach";

/** Label self-check: a known label resets the run; `limit` unknown labels in a row mean detach. */
export class LabelSelfCheck {
    mismatches = 0;

    constructor(private readonly isKnown: (label: string | null) => boolean, private readonly limit: number) {}

    observe(label: string | null): LabelVerdict {
        if (this.isKnown(label)) {
            this.mismatches = 0;
            return "emit";
        }
        this.mismatches++;
        return this.mismatches < this.limit ? "skip" : "detach";
    }
}
