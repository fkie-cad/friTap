// agent/shared/__fixtures__/nss_fenix160_arm.ts
//
// Real Thumb-2 bytes from Firefox for Android (Fenix) 160.0.1, armeabi-v7a
// libnss3.so (NSS 3.132, GNU build-id 6c8b856235c3c9117fb383e4068e793c6e2df50e).
// Addresses are file vaddrs (== module offsets for .text/.rodata).
// STATIC ONLY: verified with capstone (Phase 1b recon), never run on a device.

function hexBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
    return bytes;
}

/** Every exact "0123456789abcdef" copy in the image (the writer uses 0x341e3). */
export const HEX_TABLE_OFFSETS = [0x1b50f, 0x33ef7, 0x341e3, 0x39048, 0x40970, 0x40983];
/** client_random offset in sslSocket on this build (`add.w r3, r4, #0x428`). */
export const CLIENT_RANDOM_OFF = 0x428;

/** "CLIENT_RANDOM\0", "ECH_SECRET\0", "ECH_CONFIG\0" in .rodata. */
export const CLIENT_RANDOM_STR = 0x1fc54;
export const ECH_SECRET_STR = 0x4576a;
export const ECH_CONFIG_STR = 0x45775;

/**
 * ssl3_WriteKeyLog 0x1bb34c (hook 0x1bb34d) up to the next .ARM.exidx start
 * 0x1bb47c, trailing literal pool included (code ends at 0x1bb470).
 * Error block 0x1bb360 (`movw r0, #0xe013`) precedes `mov r4, r0` @0x1bb382;
 * `add.w r3, r4, #0x428` @0x1bb3c0; hex table `ldr r0,[pc,#0xa0]` @0x1bb3d0 +
 * `add r0, pc` @0x1bb3d2 -> 0x341e3; r4 reused as scratch from 0x1bb3d4.
 */
export const WRITER_VADDR = 0x1bb34c;
export const WRITER_CODE_END = 0x1bb470;
export const WRITER = hexBytes(
    "2de9f047002a1ebf16465268002a0ad1bde8f0874ef213000021cff6ff70bde8f04721f00dbf3f4a7a44d2f800a0daf8" +
    "0020002aecd0044608460f4622f022ebb16800eb410010f14308e3d44046b8f1010f98bf012022f046eb0028dad03946" +
    "814624f0b0eb384622f00ceb19f8002009eb000104f58563002702f120000a4602f8010b28487844dc5d02eb47052409" +
    "045d02f81740dc5d0137202f04f00f04045d6c70f0d1202201f1420781f84120b268aab3736839461d78013a4fea1515" +
    "455d01f8025b13f8015b05f00f05455d01f8015cf0d1b068400014490a223a5479440c682668304622f05ce922f062ed" +
    "daf800300121c6e90f1048464146012224f0b0e8012804bfdaf8000022f05aec206822f0e8eb4846bde8f04721f042be" +
    "0020dae7ecfc02000d8ee7ff38fc0200",
);

/**
 * 0x1c0346..0x1c0370 in fn 0x1c0218: CLIENT_RANDOM `ldr r1,[pc,#0x14]` @0x1c0354
 * (pool word 0xffe5f8f4 @0x1c036c), `add r1, pc` @0x1c035c, `bl 0x1bb34c` @0x1c035e.
 */
export const CLIENT_RANDOM_SITE_VADDR = 0x1c0346;
export const CLIENT_RANDOM_LDR = 0x1c0354;
export const CLIENT_RANDOM_ADD_PC = 0x1c035c;
export const CLIENT_RANDOM_SITE = hexBytes(
    "d4f8d803456a28461ff050e830b9054905f1180220467944faf7f5ff002098e700bf7cae0200f4f8e5ff",
);

/**
 * Whole fn 0x1d8b4c..0x1d8b9c (pools included): ECH_SECRET ldr @0x1d8b72 +
 * add r1,pc @0x1d8b7a + `bl 0x1bb34c` @0x1d8b7c; ECH_CONFIG ldr @0x1d8b80 +
 * add r1,pc @0x1d8b88, `pop.w {r4,r5,r6,lr}`, tail `b.w 0x1bb34c` @0x1d8b8e.
 */
export const ECH_TAIL_FN_VADDR = 0x1d8b4c;
export const ECH_SECRET_ADD_PC = 0x1d8b7a;
export const ECH_CONFIG_ADD_PC = 0x1d8b88;
export const ECH_TAIL_FN = hexBytes(
    "70b5d0f8ac1641b1d0f8a46c00f6a44296421cbf8d6a002d00d170bd0446284606f040ec30b9084905f1180220467944" +
    "e2f7e6fb054906f1080220467944bde87040e2f7ddbb00bfeccbe6ffe9cbe6ff",
);
