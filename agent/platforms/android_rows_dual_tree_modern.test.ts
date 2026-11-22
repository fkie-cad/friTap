// Android registry, --modern tree (use_modern=true): the counterpart of
// android_rows_dual_tree_legacy.test.ts, in its own process because use_modern is read
// once while the agent loads. Same checks, so the Fizz and OHTTP rows are proven
// identical in both trees.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../shared/frida-test-stubs.js";
import "./__fixtures__/modern_config.js";   // before the agent entry: use_modern=true
import { use_modern } from "../fritap_agent.js";
import { nss_execute_modern } from "../tls/platforms/android/nss_android.js";
import { androidRegistryRows, defineTreeIndependentRowTests, rowLabelled } from "./__fixtures__/android_rows.js";

test("modern: the agent loaded with use_modern=true and the NSS row runs the modern definition", () => {
    assert.equal(use_modern, true);
    assert.equal(rowLabelled(androidRegistryRows(), "NSS").hookFn, nss_execute_modern);
});

defineTreeIndependentRowTests("modern");
