// Run: npm run test:agent
//
// ModuleHookingType contract for the supplementary Chromium plaintext row: an
// executor that installs nothing must say so (`false`), otherwise the loader
// announces "found & will be hooked" and reports library_detected for hooks that
// never existed (e.g. Chrome without -p, or the BoringSSL locator failing).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { installChromiumPlaintextHooks } from "./chromium_plaintext.js";
import { chromium_plaintext_execute } from "../platforms/android/chromium_plaintext_android.js";
import { hookExecutorInstalled } from "../../shared/shared_structures.js";

test("chromium_plaintext_execute: declines synchronously (false) without plaintext pcap", () => {
    const outcome = chromium_plaintext_execute("libchrome.so", true);
    assert.equal(outcome, false);
    assert.equal(hookExecutorInstalled(outcome), false);
});

test("installChromiumPlaintextHooks: resolves false when nothing was installed", async () => {
    assert.equal(await installChromiumPlaintextHooks("libmonochrome.so", "libc", true), false);
});
