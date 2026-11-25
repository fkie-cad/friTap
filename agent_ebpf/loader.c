#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "capture_ring.skel.h"
#include "capture_perf.skel.h"
#include "perf_order.h"

#define ABI "fritap-ebpf/3"
#ifndef PERF_BUFFER_PAGES
#define PERF_BUFFER_PAGES 64
#endif

static const char *const symbols[] = {
    "SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex", "SSL_free",
};

enum { SYMBOL_COUNT = sizeof(symbols) / sizeof(*symbols), PROBE_COUNT = 2 * SYMBOL_COUNT - 1 };

static volatile sig_atomic_t stopping;
static const char *stage;

static void stop(int sig)
{
    (void)sig;
    stopping = 1;
}

static int report_error(int err)
{
    const char *status = "unsupported";
    if (err == ESRCH)
        status = "target_disappeared";
    else if (err == EPERM || (err == EACCES && strcmp(stage, "load_bpf")))
        status = "permission_denied";
    printf("{\"type\":\"error\",\"status\":\"%s\",\"stage\":\"%s\",\"errno\":%d}\n",
           status, stage, err);
    return 1;
}

static int target_exited(int fd)
{
    struct pollfd target = { .fd = fd, .events = POLLIN };
    return poll(&target, 1, 0) > 0;
}

static int inspect_library(int fd, size_t offsets[SYMBOL_COUNT], char *id, size_t capacity);

static int find_library(int pid, size_t offsets[SYMBOL_COUNT], char *id, size_t id_size)
{
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *file = fopen(maps, "r");
    if (!file)
        return -errno;

    char *line = NULL;
    size_t capacity = 0;
    int fd = -ENOENT;
    while (getline(&line, &capacity, file) >= 0) {
        char perms[5];
        unsigned int major_id, minor_id;
        unsigned long long inode;
        int start = 0;
        if (sscanf(line, "%*s %4s %*s %x:%x %llu %n",
                   perms, &major_id, &minor_id, &inode, &start) != 4 || !start)
            continue;
        char *path = line + start;
        path[strcspn(path, "\n")] = 0;
        const char *base = strrchr(path, '/');
        if (*path != '/' || !base ||
            (strcmp(base, "/libssl.so.3") && strcmp(base, "/libssl.so")) || perms[2] != 'x')
            continue;
        char rooted[PATH_MAX];
        if (snprintf(rooted, sizeof(rooted), "/proc/%d/root%s", pid, path) >= (int)sizeof(rooted))
            continue;
        int candidate = open(rooted, O_RDONLY | O_CLOEXEC);
        if (candidate < 0) {
            fd = -errno;
            continue;
        }
        struct stat st;
        if (fstat(candidate, &st) || st.st_ino != inode ||
            major(st.st_dev) != major_id || minor(st.st_dev) != minor_id) {
            close(candidate);
            fd = -ESTALE;
            continue;
        }
        memset(offsets, 0, sizeof(*offsets) * SYMBOL_COUNT);
        id[0] = 0;
        int error = inspect_library(candidate, offsets, id, id_size);
        if (!error) {
            fd = candidate;
            break;
        }
        close(candidate);
        fd = -error;
    }
    free(line);
    fclose(file);
    return fd;
}

static void read_build_id(Elf_Data *data, char *id, size_t capacity)
{
    size_t offset = 0, name, desc;
    GElf_Nhdr note;
    while ((offset = gelf_getnote(data, offset, &note, &name, &desc))) {
        if (note.n_type != NT_GNU_BUILD_ID || note.n_namesz != 4 ||
            memcmp((char *)data->d_buf + name, "GNU", 4) ||
            !note.n_descsz || note.n_descsz > (capacity - 1) / 2)
            continue;
        const unsigned char *bytes = (unsigned char *)data->d_buf + desc;
        for (size_t i = 0; i < note.n_descsz; i++)
            snprintf(id + 2 * i, 3, "%02x", bytes[i]);
        return;
    }
}

static size_t file_offset(Elf *elf, const GElf_Sym *sym)
{
    size_t count;
    if (elf_getphdrnum(elf, &count))
        return 0;
    for (size_t i = 0; i < count; i++) {
        GElf_Phdr segment;
        if (gelf_getphdr(elf, i, &segment) && segment.p_type == PT_LOAD &&
            (segment.p_flags & PF_X) && sym->st_value >= segment.p_vaddr &&
            sym->st_value - segment.p_vaddr < segment.p_filesz)
            return segment.p_offset + (sym->st_value - segment.p_vaddr);
    }
    return 0;
}

static int is_openssl3(Elf *elf, GElf_Shdr *section, Elf_Data *data)
{
    size_t offset = 0;
    while (offset < data->d_size) {
        GElf_Verdef definition;
        GElf_Verdaux aux;
        if (!gelf_getverdef(data, offset, &definition) ||
            definition.vd_aux >= data->d_size - offset ||
            !gelf_getverdaux(data, offset + definition.vd_aux, &aux))
            return 0;
        const char *name = elf_strptr(elf, section->sh_link, aux.vda_name);
        if (name && !strcmp(name, "OPENSSL_3.0.0"))
            return 1;
        if (!definition.vd_next || definition.vd_next >= data->d_size - offset)
            break;
        offset += definition.vd_next;
    }
    return 0;
}

static int inspect_library(int fd, size_t offsets[SYMBOL_COUNT], char *id, size_t capacity)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        return ENOEXEC;
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        return ENOEXEC;
    GElf_Ehdr header;
#if defined(__aarch64__)
    const unsigned int machine = EM_AARCH64;
#elif defined(__x86_64__)
    const unsigned int machine = EM_X86_64;
#else
#error Unsupported native architecture
#endif
    if (!gelf_getehdr(elf, &header) || gelf_getclass(elf) != ELFCLASS64 ||
        header.e_machine != machine || header.e_type != ET_DYN) {
        elf_end(elf);
        return ENOEXEC;
    }
    int openssl3 = 0;
    Elf_Scn *section = NULL;
    while ((section = elf_nextscn(elf, section))) {
        GElf_Shdr info;
        if (!gelf_getshdr(section, &info))
            continue;
        Elf_Data *data = elf_getdata(section, NULL);
        if (!data)
            continue;
        if (info.sh_type == SHT_NOTE)
            read_build_id(data, id, capacity);
        if (info.sh_type == SHT_GNU_verdef)
            openssl3 |= is_openssl3(elf, &info, data);
        if (info.sh_type != SHT_DYNSYM || !info.sh_entsize)
            continue;
        for (size_t i = 0; i < info.sh_size / info.sh_entsize; i++) {
            GElf_Sym symbol;
            if (!gelf_getsym(data, i, &symbol) || symbol.st_shndx == SHN_UNDEF ||
                GELF_ST_TYPE(symbol.st_info) != STT_FUNC)
                continue;
            const char *name = elf_strptr(elf, info.sh_link, symbol.st_name);
            for (size_t n = 0; name && n < SYMBOL_COUNT; n++)
                if (!strcmp(name, symbols[n]))
                    offsets[n] = file_offset(elf, &symbol);
        }
    }
    elf_end(elf);
    for (size_t i = 0; i < SYMBOL_COUNT; i++)
        if (!offsets[i])
            return ENOEXEC;
    return id[0] && openssl3 ? 0 : ENOEXEC;
}

static int deliver(const struct tls_event *event)
{
    const struct tls_event_header *header = &event->header;
    static const char hex[] = "0123456789abcdef";
    char payload[2 * MAX_PAYLOAD + 1];
    for (unsigned int i = 0; i < header->length; i++) {
        payload[2 * i] = hex[event->payload[i] >> 4];
        payload[2 * i + 1] = hex[event->payload[i] & 15];
    }
    payload[2 * header->length] = 0;
    if (printf("{\"type\":\"data\",\"connection\":%llu,\"write\":%u,\"ex\":%u,\"data\":\"%s\"}\n",
               header->connection, header->write, header->extended, payload) < 0)
        return -EPIPE;
    return 0;
}

static int ring_sample(void *ctx, void *record, size_t size)
{
    (void)ctx;
    const struct tls_event *event = record;
    if (size != sizeof(*event) || event->header.length > MAX_PAYLOAD)
        return -EPROTO;
    return deliver(event);
}

struct perf_reader {
    struct perf_queue queue;
    unsigned long long *notified;
    int cpus;
    int error;
};

static void perf_sample(void *ctx, int cpu, void *record, __u32 size)
{
    (void)cpu;
    struct perf_reader *reader = ctx;
    int error = queue_sample(&reader->queue, record, size);
    if (error && !reader->error)
        reader->error = error;
}

static void perf_lost(void *ctx, int cpu, __u64 lost)
{
    struct perf_reader *reader = ctx;
    if (cpu >= 0 && cpu < reader->cpus)
        reader->notified[cpu] += lost;
}

static int enable_capture(int config_fd, int pid)
{
    unsigned int key = 0;
    struct capture_config config = { .pid = pid, .enabled = pid != 0 };
    return bpf_map_update_elem(config_fd, &key, &config, BPF_ANY);
}

static void report_ready(int perf, const char *build_id, const struct utsname *kernel)
{
    printf("{\"type\":\"ready\",\"build_id\":\"%s\",\"kernel\":\"%s\",\"transport\":\"%s\"}\n",
           build_id, kernel->release, perf ? "perf" : "ring");
}

static int controller_closed(void)
{
    struct pollfd control = { .fd = STDIN_FILENO, .events = POLLIN };
    return poll(&control, 1, 0) > 0;
}

static int run(int pid, int preflight, int remote)
{
    stage = "process_identity";
    int target = syscall(SYS_pidfd_open, pid, 0);
    if (target < 0)
        return report_error(errno);
    int library = -1, err = 0;
    struct bpf_object *bpf = NULL;
    struct perf_buffer *perf_buffer = NULL;
    struct perf_reader reader = {0};
    struct cpu_state *counts = NULL;
    int use_perf = 0, capturing = 0, config_fd = -1, state_fd = -1;
    struct ring_buffer *ring = NULL;
    struct bpf_link *links[PROBE_COUNT] = {0};
    char build_id[129] = "";
    size_t offsets[SYMBOL_COUNT] = {0};
    struct utsname kernel;

    stage = "mapped_openssl";
    library = find_library(pid, offsets, build_id, sizeof(build_id));
    if (library < 0) {
        err = -library;
        if (err == ENOEXEC)
            stage = "openssl_elf";
        goto cleanup;
    }

    stage = "probe_ring_buffer";
    int probe = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, sysconf(_SC_PAGESIZE), NULL);
    int transport = select_transport(probe < 0 ? errno : 0);
    if (transport < 0) {
        err = -transport;
        goto cleanup;
    }
    if (probe >= 0)
        close(probe);
    use_perf = transport == TRANSPORT_PERF;

    stage = "open_bpf";
    size_t object_size;
    const void *object = use_perf ? capture_perf__elf_bytes(&object_size) :
                                   capture_ring__elf_bytes(&object_size);
    bpf = bpf_object__open_mem(object, object_size, NULL);
    err = -libbpf_get_error(bpf);
    if (err) {
        bpf = NULL;
        goto cleanup;
    }
    stage = "load_bpf";
    err = -bpf_object__load(bpf);
    if (err)
        goto cleanup;

    stage = "event_buffer";
    reader.cpus = libbpf_num_possible_cpus();
    if (reader.cpus < 0) {
        err = -reader.cpus;
        goto cleanup;
    }
    counts = calloc(reader.cpus, sizeof(*counts));
    reader.notified = calloc(reader.cpus, sizeof(*reader.notified));
    if (!counts || !reader.notified) {
        err = ENOMEM;
        goto cleanup;
    }
    int events_fd = bpf_object__find_map_fd_by_name(bpf, "events");
    config_fd = bpf_object__find_map_fd_by_name(bpf, "config");
    state_fd = bpf_object__find_map_fd_by_name(bpf, "state");
    if (use_perf) {
        perf_buffer = perf_buffer__new(events_fd, PERF_BUFFER_PAGES, perf_sample, perf_lost, &reader, NULL);
        err = -libbpf_get_error(perf_buffer);
        if (err)
            perf_buffer = NULL;
    } else {
        ring = ring_buffer__new(events_fd, ring_sample, NULL, NULL);
        err = -libbpf_get_error(ring);
        if (err)
            ring = NULL;
    }
    if (err)
        goto cleanup;

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", library);
    const char *program_names[] = {
        "read_enter", "read_leave", "write_enter", "write_leave",
        "read_ex_enter", "read_ex_leave", "write_ex_enter", "write_ex_leave", "free_ssl",
    };
    const char *stages[] = {
        "SSL_read entry", "SSL_read return", "SSL_write entry", "SSL_write return",
        "SSL_read_ex entry", "SSL_read_ex return", "SSL_write_ex entry", "SSL_write_ex return",
        "SSL_free entry",
    };
    for (size_t i = 0; i < PROBE_COUNT; i++) {
        stage = stages[i];
        const char *attachment_path = path;
#ifdef TEST_CONTROLS
        const char *fail = getenv("FRITAP_TEST_FAIL_ATTACHMENT");
        if (i == 2 && fail && !strcmp(fail, "1"))
            attachment_path = "/proc/self/fd/-1";
#endif
        struct bpf_program *program = bpf_object__find_program_by_name(bpf, program_names[i]);
        links[i] = bpf_program__attach_uprobe(program, i % 2, pid, attachment_path, offsets[i / 2]);
        err = -libbpf_get_error(links[i]);
        if (err) {
            links[i] = NULL;
            goto cleanup;
        }
    }
    stage = "process_identity";
    if (target_exited(target)) {
        err = ESRCH;
        goto cleanup;
    }
    stage = "kernel_version";
    if (uname(&kernel)) {
        err = errno;
        goto cleanup;
    }
    if (preflight)
        goto cleanup;

    stage = "enable_capture";
    if (enable_capture(config_fd, pid)) {
        err = errno;
        goto cleanup;
    }
    capturing = 1;
    report_ready(use_perf, build_id, &kernel);
#ifdef TEST_CONTROLS
    if (getenv("FRITAP_TEST_DELAY_DRAIN"))
        sleep(2);
#endif
    stage = "event_buffer";
    while (!stopping && !target_exited(target) && !(remote && controller_closed())) {
        int result;
        if (use_perf) {
            result = perf_buffer__poll(perf_buffer, 50);
            if (result >= 0) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                unsigned long long ns = now.tv_sec * 1000000000ULL + now.tv_nsec;
                result = perf_buffer__consume(perf_buffer);
                if (result >= 0)
                    result = queue_flush(&reader.queue, ns > PERF_REORDER_NS ? ns - PERF_REORDER_NS : 0,
                                         deliver);
                if (result >= 0)
                    result = reader.error;
            }
        } else {
            result = ring_buffer__poll(ring, 100);
        }
        if (result < 0 && result != -EINTR) {
            err = -result;
            break;
        }
    }

cleanup:
    if (capturing)
        enable_capture(config_fd, 0);
    for (int i = PROBE_COUNT - 1; i >= 0; i--)
        bpf_link__destroy(links[i]);
    if (capturing) {
        int result = use_perf ? perf_buffer__consume(perf_buffer) : ring_buffer__consume(ring);
        if (result < 0 && !err)
            err = -result;
        if (use_perf) {
            result = queue_flush(&reader.queue, ULLONG_MAX, deliver);
            if (!err)
                err = result < 0 ? -result : -reader.error;
        }
        unsigned int key = 0;
        if (bpf_map_lookup_elem(state_fd, &key, counts)) {
            if (!err) {
                err = errno;
                stage = "loss_count";
            }
        } else {
            unsigned long long lost = reader.queue.lost;
            for (int cpu = 0; cpu < reader.cpus; cpu++)
                lost += transport_loss(&counts[cpu], reader.notified[cpu]);
            printf("{\"type\":\"loss\",\"count\":%llu}\n", lost);
        }
    } else if ((!err || err == ENOENT) && target_exited(target)) {
        err = ESRCH;
        stage = "process_identity";
    }
    while (reader.queue.count)
        free(queue_pop(&reader.queue));
    free(reader.notified);
    free(counts);
    perf_buffer__free(perf_buffer);
    ring_buffer__free(ring);
    bpf_object__close(bpf);
    if (library >= 0)
        close(library);
    close(target);
    if (err)
        return report_error(err);
    if (preflight)
        report_ready(use_perf, build_id, &kernel);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts(ABI);
        return 0;
    }
    if (argc != 3 || (strcmp(argv[1], "preflight") && strcmp(argv[1], "capture") &&
                      strcmp(argv[1], "capture-remote")))
        return 2;
    char *end;
    long pid = strtol(argv[2], &end, 10);
    if (*end || pid <= 0 || pid > INT_MAX)
        return 2;
    struct sigaction action = { .sa_handler = stop };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    return run(pid, !strcmp(argv[1], "preflight"), !strcmp(argv[1], "capture-remote"));
}
