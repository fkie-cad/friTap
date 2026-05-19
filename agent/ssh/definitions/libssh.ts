// agent/ssh/definitions/libssh.ts
//
// Data-driven libssh hook definition.
//
// libssh is the lib-based SSH client/server implementation used by tools
// like the Qt/KDE ecosystem, Ansible's mitogen backend, and various git
// clients. Its key-derivation entry points differ from OpenSSH (no
// kex_derive_keys, no sshenc; instead ssh_make_sessionkey + a packet
// callback model), but the legacy executor in ssh_linux.ts probes for
// symbols via Module.findExportByName and is tolerant of either family
// being present — meaning the OpenSSH-targeted hooks simply no-op when
// running against libssh.
//
// This wrapper mirrors createOpenSshDefinition() — same delegation
// pattern — but advertises the libssh symbol set so the loader's address
// resolution surface is accurate when a future reimplementation lands.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { STANDARD_SOCKET_SYMBOLS } from "../../tls/definitions/shared_constants.js";
import { noOpClientRandomDecoder } from "../../tls/definitions/shared_factories.js";
import { ssh_detect_execute } from "../platforms/linux/ssh_linux.js";

function libsshFdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}

function libsshSessionIdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): string {
    return "";
}

const LIBSSH_LIBRARY_SYMBOLS: string[] = [
    "ssh_make_sessionkey",
    "ssh_packet_kexdh_init",
    "ssh_packet_newkeys",
    "ssh_socket_unbuffered_write",
    "ssh_packet_socket_callback",
    "ssh_channel_read",
    "ssh_channel_write",
];

export function createLibsshDefinition(): HookDefinition {
    return {
        libraryId: "ssh_libssh",
        offsetKey: "ssh_libssh",
        functions: {
            librarySymbols: LIBSSH_LIBRARY_SYMBOLS,
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [],
        fdDecoder: libsshFdDecoder,
        sessionIdDecoder: libsshSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        // readHook / writeHook intentionally undefined — see openssh.ts
        // for the rationale; legacy ssh_detect_execute owns both paths.
        keylog: {
            kind: "custom",
            install: (_addresses, moduleName, _resolvedFns, _enableDefaultFd) => {
                // Legacy ssh_detect_execute doesn't distinguish OpenSSH
                // from libssh at the executor level — the hookers inside
                // probe each symbol independently and no-op when missing.
                ssh_detect_execute(moduleName, /* is_base_hook */ true);
                return true;
            },
        },
        libraryType: "ssh_libssh",
    };
}
