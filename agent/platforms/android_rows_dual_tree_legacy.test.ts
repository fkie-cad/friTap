// Android registry, DEFAULT tree (use_modern=false, i.e. no --modern): the rows
// load_android_hooking_agent() registers. The Fizz and OHTTP rows must be the very
// same as under --modern (android_rows_dual_tree_modern.test.ts runs the identical
// checks in a process whose config handshake delivers use_modern=true).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../shared/frida-test-stubs.js";
import { use_modern } from "../fritap_agent.js";
import { nss_execute } from "../legacy/tls/platforms/android/nss_android.js";
import { androidRegistryRows, defineTreeIndependentRowTests, rowLabelled } from "./__fixtures__/android_rows.js";

test("legacy: the agent loaded with use_modern=false and the NSS row runs the legacy NSS_Android hooker", () => {
    assert.equal(use_modern, false);
    assert.equal(rowLabelled(androidRegistryRows(), "NSS").hookFn, nss_execute);
});

defineTreeIndependentRowTests("legacy");
