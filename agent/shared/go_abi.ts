// agent/shared/go_abi.ts
//
// Integer arguments of a Go function. Go does not use the C calling convention, so Frida's
// args[] (System V / AAPCS slots) do not line up with Go's parameters: read them from the
// CPU context instead.
//  - amd64 (Go >= 1.17) / arm64 (Go >= 1.18): the register-based ABIInternal.
//  - 386 / arm: no register ABI — every argument word is on the stack (the ABI0 layout).
// Either way the argument words are numbered alike: a method's receiver is argument 0, a
// string occupies two consecutive words (ptr, len), a slice three (ptr, len, cap); a uint8
// takes a whole word (the next pointer-sized field is word-aligned).

/** Go ABIInternal integer argument registers, in order. */
const GO_INT_ARG_REGISTERS: { [arch: string]: readonly string[] } = {
    x64: ["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"],
    arm64: ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15"],
};

/**
 * Stack-ABI architectures: the word size and the byte offset from sp of argument word 0 at
 * the callee's entry (first instruction):
 *   386: 0(SP) is the return address pushed by CALL, so the arguments start at 4(SP);
 *   arm: BL leaves the return address in LR, and 0(SP) is the caller's reserved slot the
 *        callee prologue saves LR into, so the arguments also start at 4(SP).
 * Only entry hooks are decoded here: the call-site probes (goMemmoveArgs) are register-ABI
 * only, as Go plaintext is not captured on 386/arm (tls/shared/go_plaintext.ts).
 */
const GO_STACK_ABI: { [arch: string]: { word: number; entry: number } } = {
    ia32: { word: 4, entry: 4 },
    arm: { word: 4, entry: 4 },
};

/** Whether `arch` passes Go arguments on the stack (386/arm) rather than in registers. */
export function isGoStackAbi(arch: string = Process.arch): boolean {
    return arch in GO_STACK_ABI;
}

/**
 * Integer argument `index` of a Go ABIInternal call (registers), or null when the
 * architecture has no register ABI (386/arm: use goArg) or `index` lies beyond the
 * register set. Registers are the same at the entry and at the call site.
 */
export function goIntArg(context: CpuContext, index: number, arch: string = Process.arch): NativePointer | null {
    const registers = GO_INT_ARG_REGISTERS[arch];
    if (!registers || index < 0 || index >= registers.length) return null;
    return (context as any)[registers[index]] ?? null;
}

/** Argument word `index` of a stack-ABI (386/arm) Go call at entry, or null on a register-ABI arch. */
export function goStackArg(context: CpuContext, index: number, arch: string = Process.arch): NativePointer | null {
    const layout = GO_STACK_ABI[arch];
    if (!layout || index < 0) return null;
    const sp: NativePointer | undefined = (context as any).sp;
    if (!sp) return null;
    return sp.add(layout.entry + index * layout.word).readPointer();
}

/**
 * Integer argument word `index` of a Go call at entry on any supported architecture: the
 * ABIInternal register on amd64/arm64, the entry stack word on 386/arm. Null when the
 * architecture is unsupported or `index` is out of range.
 */
export function goArg(context: CpuContext, index: number, arch: string = Process.arch): NativePointer | null {
    return isGoStackAbi(arch) ? goStackArg(context, index, arch) : goIntArg(context, index, arch);
}

/** recordTypeApplicationData in crypto/tls (conn.go). */
export const GO_TLS_RECORD_TYPE_APPLICATION_DATA = 23;

/**
 * crypto/tls.(*Conn).writeRecordLocked(typ recordType, data []byte) at entry (any arch):
 * c=0, typ=1 (a uint8: only the low byte is defined), data.ptr=2, data.len=3.
 */
export function goWriteRecordArgs(context: CpuContext, arch: string = Process.arch):
        { recordType: number; data: NativePointer; length: number } | null {
    const typ = goArg(context, 1, arch);
    const data = goArg(context, 2, arch);
    const length = goArg(context, 3, arch);
    if (!typ || !data || !length) return null;
    return { recordType: typ.toUInt32() & 0xff, data, length: length.toInt32() };
}

/** The SSLKEYLOGFILE fields of one crypto/tls.(*Config).writeKeyLog call. */
export interface GoKeyLogArgs {
    label: NativePointer;
    labelLength: number;
    clientRandom: NativePointer;
    clientRandomLength: number;
    secret: NativePointer;
    secretLength: number;
}

/**
 * crypto/tls.(*Config).writeKeyLog(label string, clientRandom, secret []byte) at entry:
 * c=0, label=(1 ptr, 2 len), clientRandom=(3 ptr, 4 len, 5 cap), secret=(6 ptr, 7 len, 8 cap).
 * amd64: RBX/RCX, RDI/RSI, R9/R10; arm64: X1/X2, X3/X4, X6/X7 (X5 is clientRandom's cap);
 * 386/arm: the same words on the stack at entry, sp+4 + 4*index.
 */
export function goKeyLogArgs(context: CpuContext, arch: string = Process.arch): GoKeyLogArgs | null {
    const slots = [1, 2, 3, 4, 6, 7].map((i) => goArg(context, i, arch));
    if (slots.some((s) => !s)) return null;
    const [label, labelLength, clientRandom, clientRandomLength, secret, secretLength] = slots as NativePointer[];
    return {
        label, labelLength: labelLength.toInt32(),
        clientRandom, clientRandomLength: clientRandomLength.toInt32(),
        secret, secretLength: secretLength.toInt32(),
    };
}

/**
 * runtime.memmove(to, from unsafe.Pointer, n uintptr) at its call site: to=0, from=1, n=2
 * (memmove is ABIInternal assembly on amd64/arm64, so the call site loads these registers).
 * Null on 386/arm: their call-site stack layout is not decoded (no 32-bit Go plaintext).
 */
export function goMemmoveArgs(context: CpuContext, arch: string = Process.arch):
        { to: NativePointer; from: NativePointer; length: number } | null {
    const to = goIntArg(context, 0, arch);
    const from = goIntArg(context, 1, arch);
    const length = goIntArg(context, 2, arch);
    if (!to || !from || !length) return null;
    return { to, from, length: length.toInt32() };
}
