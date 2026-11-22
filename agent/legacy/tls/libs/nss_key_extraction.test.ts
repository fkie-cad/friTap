// Unit test for the shared legacy NSS key-extraction entry point used by the
// linux / macos / android / windows legacy hookers.
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
import "../../../fritap_agent.js";

import { installLegacyNssKeyExtraction } from "./nss_key_extraction.js";

test("installLegacyNssKeyExtraction resolves the installer verdict (false: nothing installable) and never rejects", async () => {
    assert.equal(await installLegacyNssKeyExtraction("nss3.dll", {}), false);
});
