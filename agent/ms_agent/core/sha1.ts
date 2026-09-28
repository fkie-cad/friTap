/*
 * Self-contained SHA-1, pure JS/TS, no external imports.
 *
 * The MTProto engine needs a SHA-1 digest to derive the low-64 auth-key id
 * (msg_key / auth_key_id tails) without dragging in a crypto dependency into the
 * Frida agent bundle. `sha1` returns the full 20-byte digest; `sha1LowId` returns
 * only the last 8 bytes (the low 64 bits, big-endian tail), which is the form the
 * MTProto id check keys on.
 *
 * Test vector: sha1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
 */

/* Standard SHA-1 over a byte array, returning the 20-byte digest. */
export function sha1(bytes: Uint8Array): Uint8Array {
    function rotl(n, c) {
        return ((n << c) | (n >>> (32 - c))) >>> 0;
    }

    var ml = bytes.length * 8;

    // Padding: append 0x80, then zeros, until length ≡ 56 (mod 64), then 64-bit
    // big-endian message length. Total padded length is a multiple of 64.
    var withOne = bytes.length + 1;
    var totalLen = withOne + ((56 - (withOne % 64) + 64) % 64) + 8;
    var msg = new Uint8Array(totalLen);
    msg.set(bytes, 0);
    msg[bytes.length] = 0x80;
    // 64-bit big-endian bit length in the final 8 bytes. ml fits well under 2^32
    // for the inputs used here; write it into the low 32 bits, high 32 stay zero.
    msg[totalLen - 4] = (ml >>> 24) & 0xff;
    msg[totalLen - 3] = (ml >>> 16) & 0xff;
    msg[totalLen - 2] = (ml >>> 8) & 0xff;
    msg[totalLen - 1] = ml & 0xff;

    var h0 = 0x67452301;
    var h1 = 0xEFCDAB89;
    var h2 = 0x98BADCFE;
    var h3 = 0x10325476;
    var h4 = 0xC3D2E1F0;

    var w = new Array(80);

    for (var off = 0; off < totalLen; off += 64) {
        for (var i = 0; i < 16; i++) {
            var j = off + i * 4;
            w[i] = ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0;
        }
        for (var t = 16; t < 80; t++) {
            w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }

        var a = h0, b = h1, c = h2, d = h3, e = h4;

        for (var s = 0; s < 80; s++) {
            var f, k;
            if (s < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (s < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (s < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            var tmp = (rotl(a, 5) + f + e + k + w[s]) >>> 0;
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = tmp;
        }

        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }

    var out = new Uint8Array(20);
    var hs = [h0, h1, h2, h3, h4];
    for (var g = 0; g < 5; g++) {
        out[g * 4] = (hs[g] >>> 24) & 0xff;
        out[g * 4 + 1] = (hs[g] >>> 16) & 0xff;
        out[g * 4 + 2] = (hs[g] >>> 8) & 0xff;
        out[g * 4 + 3] = hs[g] & 0xff;
    }
    return out;
}

/* The low 64 bits of the SHA-1 digest: the last 8 bytes (big-endian tail), as the
 * MTProto auth-key id is defined. */
export function sha1LowId(bytes: Uint8Array): Uint8Array {
    var digest = sha1(bytes);
    return digest.slice(12, 20);
}
