// agent/ssh/definitions/openssh.ts
//
// Data-driven OpenSSH hook definition.
//
// SSH key extraction is implemented as a 500+ line cookie-correlation +
// validated struct-walk path in agent/ssh/platforms/linux/ssh_linux.ts.
// Rewriting that into a register-aware HookDefinition is out of scope for
// the use_modern parity migration, so this definition acts as a THIN
// MODERN WRAPPER: it registers OpenSSH's known symbols (so the loader's
// address-resolution scaffolding has accurate input) and delegates the
// actual hook installation to the legacy ssh_detect_execute() function
// via keylog.kind: "custom".
//
// Observable behaviour is identical to legacy, but the code path now
// routes through executeFromDefinition(), making `use_modern=true` a
// real toggle rather than a paper one.
//
// A future PR can replace the delegation with a full register-aware
// reimplementation without changing the call site in
// agent/platforms/{linux,android,macos}.ts.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { STANDARD_SOCKET_SYMBOLS } from "../../tls/definitions/shared_constants.js";
import { noOpClientRandomDecoder } from "../../tls/definitions/shared_factories.js";
import { ssh_detect_execute } from "../platforms/linux/ssh_linux.js";

function opensshFdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}

function opensshSessionIdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): string {
    return "";
}

const OPENSSH_LIBRARY_SYMBOLS: string[] = [
    "kex_derive_keys",
    "kex_send_kexinit",
    "kex_input_kexinit",
    "ssh_set_newkeys",
    "cipher_init",
    "ssh_packet_send2_wrapped",
    "ssh_packet_read_poll2",
    "sshbuf_ptr",
    "sshbuf_len",
];

export function createOpenSshDefinition(): HookDefinition {
    return {
        libraryId: "ssh_openssh",
        offsetKey: "ssh_openssh",
        functions: {
            librarySymbols: OPENSSH_LIBRARY_SYMBOLS,
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [],
        fdDecoder: opensshFdDecoder,
        sessionIdDecoder: opensshSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        // readHook / writeHook intentionally undefined — SSH plaintext
        // capture lives inside installSshPacketHooks() which is wired up
        // by the legacy ssh_detect_execute() invoked from keylog.install.
        keylog: {
            kind: "custom",
            install: (_addresses, moduleName, _resolvedFns, _enableDefaultFd) => {
                // Delegate to the legacy executor. It handles cookie
                // correlation, kex_derive_keys, cipher_init, sshenc-walk
                // fallback, and packet plaintext extraction in one place.
                ssh_detect_execute(moduleName, /* is_base_hook */ true);
                return true;
            },
        },
        libraryType: "ssh_openssh",
    };
}
