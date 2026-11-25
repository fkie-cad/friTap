#ifndef FRITAP_EBPF_REGISTERS_H
#define FRITAP_EBPF_REGISTERS_H

/* Uprobes see the native 64-bit user register frame at the start of pt_regs. */
#if defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long regs[31];
};
#define ARG1(ctx) ((ctx)->regs[0])
#define ARG2(ctx) ((ctx)->regs[1])
#define ARG4(ctx) ((ctx)->regs[3])
#define RESULT(ctx) ((ctx)->regs[0])
#elif defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long r15, r14, r13, r12, bp, bx;
    unsigned long r11, r10, r9, r8, ax, cx, dx, si, di;
};
#define ARG1(ctx) ((ctx)->di)
#define ARG2(ctx) ((ctx)->si)
#define ARG4(ctx) ((ctx)->cx)
#define RESULT(ctx) ((ctx)->ax)
#else
#error Unsupported native BPF architecture
#endif

#endif
