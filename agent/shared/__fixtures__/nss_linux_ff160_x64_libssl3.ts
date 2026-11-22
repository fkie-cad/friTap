// agent/shared/__fixtures__/nss_linux_ff160_x64_libssl3.ts
//
// Real code bytes from desktop Firefox 160.0.1 for Linux x86_64, libssl3.so
// (NSS 3.132, NOT folded into libnss3: SSL code and the keylog labels live in
// libssl3.so; GNU build-id 7cf81e8be64dd32cf557bfc7a265ad893c4054d8). Addresses
// are file vaddrs (== module offsets); .text vaddr = file offset + 0x1000.
//
// Shape difference from Fenix: ssl3_RecordKeyLog is out of line here, so the
// CLIENT_RANDOM site's first call is RecordKeyLog (no hex table), which reaches
// the writer by a tail jmp (depth-1 candidate). The writer's loop is unrolled by
// two, so it applies both ss+0x650 and ss+0x651 (the odd one is not plausible).

function hexBytes(hex: string): Uint8Array {
    return new Uint8Array(hex.match(/../g)!.map((b) => parseInt(b, 16)));
}

/** The only "0123456789abcdef" copy in libssl3.so (referenced by the writer @0x32e03). */
export const LINUX_HEX_TABLE_OFFSETS = [0x12c30];
export const LINUX_CLIENT_RANDOM_OFF = 0x650;

/**
 * ssl3_WriteKeyLog, full body 0x32d80..0x32f99 (FDE bounds). `mov r13, rdi` @0x32db3; hex table
 * `lea rcx, [rip-0x201da]` @0x32e03 -> 0x12c30; `movzx edi, byte [r13+rsi+0x650]` @0x32e10/0x32e24
 * and `[r13+rsi+0x651]` @0x32e39/0x32e4e.
 */
export const LINUX_WRITER_VADDR = 0x32d80;
export const LINUX_WRITER_END = 0x32f99;
export const LINUX_WRITER = hexBytes(
    "55415741564155415453504885d20f846e0100004989d748837a08000f846001000048833dd6820400000f8452010000" +
    "4889f54989fd4889f7e8b2020400418b4f10448d34484183c6434c89f7e88e0204004885c00f84270100004989c44889" +
    "c34c89e74889eee8a40204004889efe87c02040089c14180040c208d50014c01e231f6488d0d26fefdff660f1f440000" +
    "410fb6bc3550060000c1ef040fb63c0f40883c72410fb6bc355006000083e70f0fb63c0f40887c7201410fb6bc355106" +
    "0000c1ef040fb63c0f40887c7202410fb6bc355106000083e70f0fb63c0f40887c72034883c6024883fe2075a38d5041" +
    "83c042c6041320418b7f104885ff0f848d000000498b570889c64901f483ff010f847f0000004189f84183e0fe31f690" +
    "440fb60c3241c1e904450fb60c0945880c24440fb60c324183e10f450fb60c0945884c2401440fb64c320141c1e90445" +
    "0fb60c0945884c2402440fb64c32014183e10f450fb60c0945884c24034983c4044883c6024939f075a640f6c7017436" +
    "eb154883c4085b415c415d415e415f5dc331c9eb2731f60fb63c32c1ef040fb63c0f41883c240fb6143283e20f0fb60c" +
    "0a41884c2401418b4f1001c901c1c6040b0a488b3d3f810400e872050400488b0d2b810400ba010000004889df4c89f6" +
    "e87b0704004883f801750c488b3d0e810400e879070400488b3d0a810400e84d0504004889df4883c4085b415c415d41" +
    "5e415f5de9e7000400");

/** ssl3_RecordKeyLog 0x32d40..0x32d7b: PK11_ExtractKeyValue, PK11_GetKeyData, tail `jmp 0x32d80`. */
export const LINUX_RECORD_KEYLOG_VADDR = 0x32d40;
export const LINUX_RECORD_KEYLOG = hexBytes(
    "41574156534989d74889f34989fe4889d7e86a09040085c074065b415e415fc34c89ffe8680904004c89f74889de4889" +
    "c25b415e415fe905000000");

/** CLIENT_RANDOM site tail of fn 0x3a0d0..0x3a2c0: `lea rsi, [rip-0x2ca5c]` (-> 0xd850) @0x3a2a5, `call 0x32d40` @0x3a2af. */
export const LINUX_CLIENT_RANDOM_LEA = 0x3a2a5;
export const LINUX_CLIENT_RANDOM_FN = { start: 0x3a0d0, end: 0x3a2c0 };
export const LINUX_CLIENT_RANDOM_SITE = hexBytes(
    "488d35a435fdff4889dfe88c8affff31c0e9c1feffffe8b09f0300");