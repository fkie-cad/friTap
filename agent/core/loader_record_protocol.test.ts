// Run: npm run test:agent
//
// executeFromDefinition awaits the hooking pipeline before it attaches anything,
// so the loader's synchronous record-protocol binding (record_protocol.ts) has
// already ended by then. The loader must re-bind the protocol it was called under,
// or every SSH/IPsec/QUIC record of a definition-driven lib is tagged "tls" under
// --protocol auto/all.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../shared/frida-test-stubs.js";
// Load the agent entry first so the loader's import cycle resolves in production order.
import "../fritap_agent.js";
import { executeFromDefinition } from "./loader.js";
import { activeRecordProtocol, runHookExecutor } from "../shared/record_protocol.js";

function definitionRecording(seen: Array<string | undefined>): any {
    return {
        libraryId: "test_lib",
        libraryType: "test",
        offsetKey: "test_lib",
        functions: { librarySymbols: [], socketSymbols: [] },
        nativeFunctions: [],
        keylog: { kind: "none" },
        extraHooks: [{ install: () => { seen.push(activeRecordProtocol()); } }],
    };
}

test("executeFromDefinition: hooks installed after the pipeline await keep the row's record protocol", async () => {
    const seen: Array<string | undefined> = [];
    const pending = runHookExecutor("ssh", () =>
        executeFromDefinition(definitionRecording(seen), "libssh_test.so", "libc", false, false));
    assert.equal(activeRecordProtocol(), undefined, "binding ends with the synchronous executor");
    await pending;
    assert.deepEqual(seen, ["ssh"]);
});

test("executeFromDefinition: outside any bound executor no protocol is invented", async () => {
    const seen: Array<string | undefined> = [];
    await executeFromDefinition(definitionRecording(seen), "libplain_test.so", "libc", false, false);
    assert.deepEqual(seen, [undefined]);
});
