// Regression tests for the SSH/IPSec "thin modern wrapper" definitions
// (OpenSSH, libssh, strongSwan) and how they survive a `-p`-only run.
//
// Run: npm run test:agent
//
// WHY THIS FILE EXISTS
// --------------------
// These three non-TLS wrappers route BOTH key extraction and packet/plaintext
// capture through the legacy ssh_detect_execute / ipsec_detect_execute
// executor. That executor self-gates keys on keylog_enabled and packets on
// pcap_enabled internally, so a `-p`-only run (packets, no keys) must still
// reach it. The loader gates the *keylog* install on keylog_enabled but runs
// extraHooks unconditionally (executeFromDefinition step 7). The correct wiring
// is therefore: keylog.kind === "none" (nothing for the gate to skip) and the
// executor call carried in extraHooks (always runs). These tests lock that down
// so the executor can't drift back into keylog.install, where a keys-off run
// would skip it — the original regression.

import { test } from "node:test";
import assert from "node:assert/strict";

// Import order matters: this side-effect setup installs the Frida globals
// (send/recv/rpc/Module/Interceptor/...) the definition + executor import graph
// needs, BEFORE the heavy modules below evaluate.
import "../shared/frida-test-stubs.js";

import { createOpenSshDefinition } from "../ssh/definitions/openssh.js";
import { createLibsshDefinition } from "../ssh/definitions/libssh.js";
import { createStrongswanDefinition } from "../ipsec/definitions/strongswan.js";

const CASES = [
    { name: "ssh_openssh", make: createOpenSshDefinition },
    { name: "ssh_libssh", make: createLibsshDefinition },
    { name: "strongswan", make: createStrongswanDefinition },
];

test("SSH/IPSec wrappers keep the executor out of the keylog gate", () => {
    for (const { name, make } of CASES) {
        const def = make();
        // kind "none" => the loader's keylog gate has nothing to install/skip
        // for these; all behaviour lives in extraHooks instead.
        assert.equal(def.keylog.kind, "none", `${name} keylog kind must be "none"`);
        // The old selfGated special-case is gone — the gate no longer needs it.
        assert.equal(
            (def as { selfGated?: boolean }).selfGated, undefined,
            `${name} must not set the removed selfGated flag`,
        );
        // The executor call must be carried in extraHooks (ungated step 7).
        assert.ok(
            Array.isArray(def.extraHooks) && def.extraHooks.length > 0,
            `${name} must carry the legacy executor in extraHooks`,
        );
    }
});

test("SSH/IPSec wrappers install via extraHooks on a -p-only run", () => {
    // keylog_enabled defaults to false in the imported agent module, so this is
    // exactly the `-p`-only scenario. Running the extraHooks (what the loader's
    // ungated step 7 does) must still reach the legacy executor, which announces
    // itself with a library_detected message regardless of keys/packets.
    const G = globalThis as { send?: (m: unknown) => void };
    for (const { name, make } of CASES) {
        const def = make();
        const savedSend = G.send;
        const contentTypes: string[] = [];
        G.send = (message: unknown) => {
            if (message && typeof message === "object" && "contentType" in message) {
                contentTypes.push(String((message as { contentType: unknown }).contentType));
            }
        };
        try {
            for (const extra of def.extraHooks!) {
                extra.install({}, `/fake/path/${name}.so`, {}, false);
            }
        } finally {
            G.send = savedSend;
        }
        assert.ok(
            contentTypes.includes("library_detected"),
            `${name} extraHooks must invoke the legacy executor (expected a ` +
            `library_detected message, got: ${contentTypes.join(", ") || "none"})`,
        );
    }
});
