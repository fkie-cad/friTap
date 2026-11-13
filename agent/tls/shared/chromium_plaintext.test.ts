// Run: npm run test:agent
//
// ModuleHookingType contract for the supplementary Chromium plaintext row: an
// executor that installs nothing must say so (`false`), otherwise the loader
// announces "found & will be hooked" and reports library_detected for hooks that
// never existed (e.g. Chrome without -p, or the BoringSSL locator failing).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import {
    installChromiumPlaintextHooks, attachChromiumPlaintextHooks, chromiumPlaintextHost, exportsSslRecordApi,
} from "./chromium_plaintext.js";
import { SslPlaintextHooks } from "../../shared/ssl_plaintext_hooks.js";
import { isSocketFdTrackerInstalled } from "../../shared/socket_fd_tracker.js";
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

test("attachChromiumPlaintextHooks: attaches only the located hooks", () => {
    const attached: string[] = [];
    const hooks = { attachRead: () => { attached.push("read"); }, attachWrite: () => { attached.push("write"); } };
    const located: any = { isNull: () => false };
    attachChromiumPlaintextHooks(hooks, { sslRead: located, sslWrite: null });
    assert.deepEqual(attached, ["read"]);
    assert.equal(isSocketFdTrackerInstalled(), false, "the fake hooks arm nothing");
});

// Chromium's SSL objects never expose a socket fd, so the fd tracker is armed when the
// hooks attach instead of lazily on the first fd-less record.
test("the Chromium host is fd-less, so attaching its hooks arms the fd tracker early", () => {
    const host = chromiumPlaintextHost("libmonochrome.so", "libc", true);
    assert.equal(host.fdLess, true);
    const hooks = new SslPlaintextHooks(host, { readmod: null, writemod: null }, false);
    const located: any = { isNull: () => false };
    assert.equal(isSocketFdTrackerInstalled(), false, "nothing armed the tracker before");
    attachChromiumPlaintextHooks(hooks, { sslRead: located, sslWrite: located });
    assert.equal(isSocketFdTrackerInstalled(), true, "armed at install, not on the first record");
});

// Cronet builds that export SSL_read/SSL_write are hooked by their primary row;
// the locator path must stay out so records are not emitted twice.
test("exportsSslRecordApi: true when SSL_read or SSL_write is exported, false when stripped", () => {
    const moduleExporting = (names: string[]) => ({
        findExportByName: (name: string) => (names.includes(name) ? ptr(0x1000) : null),
    });
    assert.equal(exportsSslRecordApi(moduleExporting(["SSL_read", "SSL_write"])), true);
    assert.equal(exportsSslRecordApi(moduleExporting(["SSL_write"])), true);
    assert.equal(exportsSslRecordApi(moduleExporting(["SSL_CTX_new"])), false);
    assert.equal(exportsSslRecordApi(moduleExporting([])), false);
});
