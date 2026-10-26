// Unit tests for parseMapsPeImages (proc_maps.ts): locating PE images that Frida
// does not list as modules on Wine >= 9.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../shared/frida-test-stubs.js";

import { parseMapsPeImages } from "./proc_maps.js";

const MAPS = [
    "6fffedec0000-6fffedec1000 r--p 00000000 103:02 1234 /home/u/app/Release/libcef.dll",
    "6fffedec1000-6ffffaa00000 r-xp 00001000 103:02 1234 /home/u/app/Release/libcef.dll",
    "140000000-140001000 r--p 00000000 103:02 99 /home/u/app/Release/cefclient.exe",
    "6ffffe000000-6ffffe001000 r--p 00000000 103:02 77 /usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll",
    "7f0000000000-7f0000001000 r--p 00000000 103:02 55 /usr/lib/x86_64-linux-gnu/libc.so.6",
    "7f0000100000-7f0000101000 ---p 00000000 00:00 0 /home/u/app/Release/guard.dll",
    "7f0000200000-7f0000201000 rw-p 00000000 00:00 0",
    "6fff00000000-6fff00001000 r--p 00000000 103:02 88 /home/u/My Games/Launcher.EXE",
].join("\n");

test("parseMapsPeImages: header mappings of .dll/.exe only, in order", () => {
    assert.deepEqual(parseMapsPeImages(MAPS), [
        { base: "0x6fffedec0000", path: "/home/u/app/Release/libcef.dll", name: "libcef.dll" },
        { base: "0x140000000", path: "/home/u/app/Release/cefclient.exe", name: "cefclient.exe" },
        { base: "0x6ffffe000000", path: "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll", name: "ntdll.dll" },
        { base: "0x6fff00000000", path: "/home/u/My Games/Launcher.EXE", name: "Launcher.EXE" },
    ]);
});

test("parseMapsPeImages: empty / garbage input", () => {
    assert.deepEqual(parseMapsPeImages(""), []);
    assert.deepEqual(parseMapsPeImages("not a maps line"), []);
});
