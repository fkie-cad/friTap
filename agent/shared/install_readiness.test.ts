// Tests for the hook-installation readiness latch (install_readiness.ts).
//
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { beginAsyncInstall, onInstallsSettled, resetInstallReadinessForTests } from "./install_readiness.js";

beforeEach(() => resetInstallReadinessForTests());

test("fires immediately when no deferred install is pending", () => {
    let fired = 0;
    onInstallsSettled(() => fired++);
    assert.equal(fired, 1);
});

test("waits until every deferred install has finished, then fires once", () => {
    let fired = 0;
    const doneA = beginAsyncInstall();
    const doneB = beginAsyncInstall();
    onInstallsSettled(() => fired++);
    assert.equal(fired, 0);
    doneA();
    assert.equal(fired, 0);
    doneB();
    assert.equal(fired, 1);
    beginAsyncInstall()();   // a later install must not re-fire the consumed callback
    assert.equal(fired, 1);
});

test("a repeated done() call does not count twice", () => {
    let fired = 0;
    const doneA = beginAsyncInstall();
    beginAsyncInstall();
    onInstallsSettled(() => fired++);
    doneA();
    doneA();
    assert.equal(fired, 0);
});
