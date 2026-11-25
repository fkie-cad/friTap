/* Readiness check only. Creates transient objects and never attaches a program. */
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int probe(enum bpf_cmd command, union bpf_attr *attributes)
{
    int fd = syscall(__NR_bpf, command, attributes, sizeof(*attributes));
    if (fd < 0)
        return errno;
    close(fd);
    return 0;
}

int main(void)
{
    union bpf_attr attributes = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 1,
    };
    int map_error = probe(BPF_MAP_CREATE, &attributes);
    const struct bpf_insn instructions[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    static const char license[] = "GPL";
    memset(&attributes, 0, sizeof(attributes));
    attributes.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attributes.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
    attributes.insns = (__u64)(unsigned long)instructions;
    attributes.license = (__u64)(unsigned long)license;
    int program_error = probe(BPF_PROG_LOAD, &attributes);
    printf("{\"map_errno\":%d,\"program_errno\":%d}\n", map_error, program_error);
    return 0;
}
