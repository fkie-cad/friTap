// Unit tests for the Windows and Wine NSS HPKE (OHTTP) registry rows
// (agent/platforms/windows.ts, agent/platforms/wine.ts).
//
// Run: npm run test:agent
//
// WHY: the Windows row matched /^(nspr|NSPR)[0-9]*\.dll/ and the definition looked for
// PK11_HPKE_* in `*libnss*`, which never matches nss3.dll — so OHTTP was never hooked on
// Windows (Firefox folds NSPR/ssl3 into nss3.dll; there is no nspr4.dll at all), and Wine
// had no HPKE row. Neither platform file can be imported under Node, so the rows are read
// from the source text by their unique `library: "NSS HPKE (OHTTP)"` label.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import "../shared/frida-test-stubs.js";
import { NSS3_MODULE_NAME } from "../tls/libs/nss_windows_libraries.js";

const here = dirname(fileURLToPath(import.meta.url));

function hpkeRow(file: string): string {
    const lines = readFileSync(join(here, file), "utf8").split("\n").filter((l) => l.includes('library: "NSS HPKE (OHTTP)"'));
    assert.equal(lines.length, 1, `${file}: expected exactly one NSS HPKE row`);
    return lines[0];
}

for (const file of ["windows.ts", "wine.ts"]) {
    test(`${file}: HPKE row uses the shared nss3.dll pattern, is supplementary, has the Windows executor`, () => {
        const row = hpkeRow(file);
        assert.match(row, /pattern: NSS3_MODULE_NAME,/);
        assert.match(row, /hookFn: nss_hpke_execute_windows,/);
        assert.match(row, /libraryType: "nss_hpke"/);
        assert.match(row, /supplementary: true/);
        assert.doesNotMatch(row, /nspr\|NSPR/);
    });
}

test("the HPKE module pattern matches (lib)nss3.dll in any case, not NSPR / other NSS DLLs / ELF", () => {
    for (const name of ["nss3.dll", "NSS3.DLL", "libnss3.dll"]) {
        assert.ok(NSS3_MODULE_NAME.test(name), name);
    }
    for (const name of ["nspr4.dll", "libnspr4.dll", "ssl3.dll", "nssutil3.dll", "softokn3.dll",
        "libnss3.so", "libnss3.dylib", "nss3.dll.mui", "libssl-3-x64.dll"]) {
        assert.ok(!NSS3_MODULE_NAME.test(name), name);
    }
});
