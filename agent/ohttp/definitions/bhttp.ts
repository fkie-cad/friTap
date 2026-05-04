import { sendWithProtocol } from "../../shared/shared_structures.js";

/** RFC 9292 known-length framing only: 0x00=request, 0x01=response.
 *  Indeterminate-length (0x02/0x03) is excluded — Python parser doesn't support it yet. */
export function looksLikeBhttp(dataPtr: NativePointer, len: number): boolean {
    if (len < 2) return false;
    const framing = dataPtr.readU8();
    return framing === 0x00 || framing === 0x01;
}

export function sendOhttpPlaintext(direction: string, source: string, data: ArrayBuffer | null): void {
    if (!data) return;
    sendWithProtocol({ contentType: "ohttp_plaintext", direction, source }, data);
}
