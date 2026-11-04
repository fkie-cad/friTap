// agent/ssh/shared/sshbuf_view.ts
//
// Crash-safe reading of OpenSSH `struct sshbuf` objects and the structures that hold them.
//
// WHY this exists: the SSH hooks must discover struct offsets at runtime (struct kex and
// struct session_state move with OpenSSH version and build flags), which means looking at
// many candidate pointers that are NOT sshbufs. Calling the target's own sshbuf_len() /
// sshbuf_ptr() on such a candidate is fatal: sshbuf_check_sanity() treats a malformed buffer
// as memory corruption and does `raise(SIGSEGV)` with the default handler restored, killing
// the process (that is how ssh died right after start under friTap). Everything here
// therefore reads the struct directly with guarded reads and never calls into the target.
//
// struct sshbuf (sshbuf.c):
//     u_char *d; const u_char *cd; size_t off, size, max_size, alloc; int readonly;
//     [int dont_free;]  u_int refcount; struct sshbuf *parent;
// `dont_free` exists up to OpenSSH 8.x (Ubuntu 22.04's 8.9p1 has it; Debian 12's 9.2p1 no
// longer does), which moves refcount by 4 bytes. Only the first six (pointer-sized) fields
// locate the data; readonly and refcount (either position) only sanity-check the candidate.

/** sshbuf.h SSHBUF_SIZE_MAX: no valid buffer can be larger. */
export const SSHBUF_SIZE_MAX = 0x8000000;
/** sshbuf.h SSHBUF_REFS_MAX. */
const SSHBUF_REFS_MAX = 0x100000;
/** KEX_COOKIE_LEN: the random cookie that starts every SSH_MSG_KEXINIT body. */
export const KEX_COOKIE_LEN = 16;
/** Longest kex name-list we accept as plausible (real ones are a few hundred bytes). */
const MAX_NAME_LIST_LEN = 4096;

/** A validated view of one sshbuf: the readable bytes are [data, data + len). */
export interface SshbufView {
    /** cd + off: the first unread byte (what sshbuf_ptr() returns). */
    data: NativePointer;
    /** size - off (what sshbuf_len() returns). */
    len: number;
    /** The buffer start (cd) and read offset, for callers that need consumed bytes. */
    base: NativePointer;
    off: number;
}

function readSize(p: NativePointer): number {
    return Process.pointerSize === 8 ? Number(p.readU64()) : p.readU32();
}

/**
 * The sshbuf at `buf`, or null when `buf` is not (readable as) a sane sshbuf.
 * Mirrors sshbuf_check_sanity() so a pointer accepted here would also pass the target's
 * own check — but rejects instead of aborting. Never throws.
 */
export function readSshbuf(buf: NativePointer | null | undefined): SshbufView | null {
    try {
        if (!buf || buf.isNull()) return null;
        const ps = Process.pointerSize;
        const d = buf.readPointer();
        const cd = buf.add(ps).readPointer();
        const off = readSize(buf.add(2 * ps));
        const size = readSize(buf.add(3 * ps));
        const maxSize = readSize(buf.add(4 * ps));
        const alloc = readSize(buf.add(5 * ps));
        const readonly = buf.add(6 * ps).readS32();
        if (cd.isNull()) return null;
        if (!readonly && !d.equals(cd)) return null;
        if (!plausibleRefcount(buf.add(6 * ps + 4))) return null;
        if (maxSize > SSHBUF_SIZE_MAX || alloc > maxSize || size > alloc || off > size) return null;
        return { data: cd.add(off), len: size - off, base: cd, off };
    } catch {
        return null;
    }
}

/** A sane refcount at `at` (OpenSSH >= 9), or `int dont_free` (0/1) followed by one (8.x). */
function plausibleRefcount(at: NativePointer): boolean {
    const sane = (v: number) => v >= 1 && v <= SSHBUF_REFS_MAX;
    if (sane(at.readU32())) return true;
    const dontFree = at.readS32();
    return (dontFree === 0 || dontFree === 1) && sane(at.add(4).readU32());
}

/** A pointer read at `base + offset`, or null when unreadable. Never throws. */
export function readPointerAt(base: NativePointer, offset: number): NativePointer | null {
    try {
        if (base.isNull()) return null;
        const p = base.add(offset).readPointer();
        return p.isNull() ? null : p;
    } catch {
        return null;
    }
}

/**
 * The NUL-terminated ASCII string at `p` if its terminator lies within `max` bytes, else
 * null. Frida's readCString(size) reads exactly `size` bytes — past the NUL into whatever
 * follows — so it cannot bound a read of an unverified pointer. Never throws.
 */
export function readShortCString(p: NativePointer | null, max: number): string | null {
    try {
        if (!p || p.isNull()) return null;
        let out = "";
        for (let i = 0; i < max; i++) {
            const c = p.add(i).readU8();
            if (c === 0) return out;
            out += String.fromCharCode(c);
        }
        return null;
    } catch {
        return null;
    }
}

function readU32BE(p: NativePointer): number {
    return ((p.readU8() << 24) | (p.add(1).readU8() << 16) | (p.add(2).readU8() << 8) | p.add(3).readU8()) >>> 0;
}

/**
 * Whether `view` holds a KEXINIT body as kept in kex->my / kex->peer:
 * `cookie[16] || string kex_algorithms || ...` (no message-type byte — OpenSSH stores the
 * body after SSH_MSG_KEXINIT). The first name-list must be printable algorithm names.
 */
export function isKexinitBody(view: SshbufView | null): boolean {
    try {
        if (!view || view.len < KEX_COOKIE_LEN + 4 + 1) return false;
        const listLen = readU32BE(view.data.add(KEX_COOKIE_LEN));
        if (listLen < 1 || listLen > MAX_NAME_LIST_LEN || listLen > view.len - KEX_COOKIE_LEN - 4) return false;
        const names = view.data.add(KEX_COOKIE_LEN + 4).readByteArray(Math.min(listLen, 64));
        if (!names) return false;
        return /^[a-z0-9@.,+_=-]+$/i.test(String.fromCharCode(...new Uint8Array(names)));
    } catch {
        return false;
    }
}

/** The 16-byte cookie of a KEXINIT body buffer as hex, or null. */
export function kexinitCookie(buf: NativePointer | null, toHex: (b: ArrayBuffer) => string): string | null {
    const view = readSshbuf(buf);
    if (!isKexinitBody(view)) return null;
    try {
        const bytes = view!.data.readByteArray(KEX_COOKIE_LEN);
        return bytes ? toHex(bytes) : null;
    } catch {
        return null;
    }
}

/**
 * The shared secret K as Wireshark's `SHARED_SECRET` expects it: the *contents* of the
 * value kex_derive_keys() receives. OpenSSH hands it the wire encoding — `mpint K`
 * (curve25519 / ECDH / DH) or `string K` (sntrup761 / mlkem768 hybrids), i.e. a u32 length
 * prefix — and Wireshark adds that encoding itself, so a prefixed value derives wrong keys.
 */
export function sharedSecretBytes(view: SshbufView | null): ArrayBuffer | null {
    try {
        if (!view || view.len <= 0) return null;
        if (view.len > 4 && readU32BE(view.data) === view.len - 4) {
            return view.data.add(4).readByteArray(view.len - 4);
        }
        return view.data.readByteArray(view.len);
    } catch {
        return null;
    }
}

/** session_state (packet.c) opens with `int connection_in; int connection_out;`. */
const CONNECTION_FD_OFFSET = { in: 0, out: 4 } as const;
/** Larger values are not descriptors a process holds (RLIMIT_NOFILE tops out far below). */
const MAX_PLAUSIBLE_FD = 1 << 20;

/**
 * ssh->state->connection_in / connection_out: what ssh_packet_get_connection_in() /
 * _out() return, read without calling into the target (stripped builds do not export
 * those accessors). struct ssh begins with `struct session_state *state`, and
 * session_state with the two descriptors; both layouts are unchanged since OpenSSH 6.x.
 * Returns -1 when unreadable or not a plausible descriptor. Never throws.
 */
export function readConnectionFd(ssh: NativePointer, direction: "in" | "out"): number {
    try {
        const state = readPointerAt(ssh, 0);
        if (state === null) return -1;
        const fd = state.add(CONNECTION_FD_OFFSET[direction]).readS32();
        return fd >= 0 && fd < MAX_PLAUSIBLE_FD ? fd : -1;
    } catch {
        return -1;
    }
}

/** Offsets of `struct kex *` in struct ssh and of `kex->my` in struct kex (peer = my + ptr). */
export interface KexLayout {
    kexInSsh: number;
    myInKex: number;
}

/** Upper bounds of the offset probes (struct ssh's kex is the 2nd field; my is ~80 bytes in). */
const SSH_PROBE_BYTES = 128;
const KEX_PROBE_BYTES = 512;

/**
 * Locate ssh->kex and kex->my by content: the first `struct kex *` candidate in struct ssh
 * whose interior holds a KEXINIT-body sshbuf followed by another sane sshbuf (kex->peer).
 * Call once kex_send_kexinit has filled kex->my. Returns null when nothing matches.
 */
export function probeKexLayout(ssh: NativePointer): KexLayout | null {
    const ps = Process.pointerSize;
    for (let kexInSsh = 0; kexInSsh < SSH_PROBE_BYTES; kexInSsh += ps) {
        const kex = readPointerAt(ssh, kexInSsh);
        if (!kex) continue;
        for (let myInKex = 0; myInKex < KEX_PROBE_BYTES; myInKex += ps) {
            const my = readPointerAt(kex, myInKex);
            if (!my || !isKexinitBody(readSshbuf(my))) continue;
            if (readSshbuf(readPointerAt(kex, myInKex + ps)) === null) continue;
            return { kexInSsh, myInKex };
        }
    }
    return null;
}

/**
 * RFC 4253 §6 framing of one SSH message (`type || payload`): u32 packet_length,
 * u8 padding_length, message, padding. The padding is synthetic (4 zero bytes): the real
 * padding is random, never part of the plaintext, and on the send side not yet generated.
 */
export function frameSshMessage(message: Uint8Array): ArrayBuffer {
    const PAD = 4;
    const out = new Uint8Array(4 + 1 + message.length + PAD);
    const packetLength = 1 + message.length + PAD;
    out[0] = (packetLength >>> 24) & 0xff;
    out[1] = (packetLength >>> 16) & 0xff;
    out[2] = (packetLength >>> 8) & 0xff;
    out[3] = packetLength & 0xff;
    out[4] = PAD;
    out.set(message, 5);
    return out.buffer;
}
