// --- Helper functions ---

function devlog(msg) {
    if (_debug) {
        send({ contentType: "devlog", message: "[" + _protocol + "] " + msg });
    }
}

function readBytes(ptr, size) {
    if (ptr.isNull()) {
        devlog("readBytes: null pointer");
        return new ArrayBuffer(0);
    }
    try {
        return ptr.readByteArray(size);
    } catch (e) {
        devlog("readBytes failed: " + e.message);
        return new ArrayBuffer(0);
    }
}

function toHex(buffer) {
    if (!buffer || buffer.byteLength === 0) return "";
    var bytes = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i].toString(16);
        hex += (b.length === 1 ? "0" : "") + b;
    }
    return hex;
}

function toBase64(buffer) {
    if (!buffer || buffer.byteLength === 0) return "";
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    // Use Frida's btoa if available, otherwise manual
    if (typeof btoa !== "undefined") {
        return btoa(binary);
    }
    // Fallback base64 encoding
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var result = "";
    var i = 0;
    while (i < bytes.length) {
        var a = bytes[i++] || 0;
        var b = bytes[i++] || 0;
        var c = bytes[i++] || 0;
        var triplet = (a << 16) | (b << 8) | c;
        result += chars[(triplet >> 18) & 0x3F];
        result += chars[(triplet >> 12) & 0x3F];
        result += (i - 2 <= bytes.length) ? chars[(triplet >> 6) & 0x3F] : "=";
        result += (i - 1 <= bytes.length) ? chars[triplet & 0x3F] : "=";
    }
    return result;
}
