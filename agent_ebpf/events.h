#ifndef FRITAP_EBPF_EVENTS_H
#define FRITAP_EBPF_EVENTS_H

#define MAX_PAYLOAD 16384
#define MAX_CHUNKS 64

struct capture_config {
    unsigned int pid;
    unsigned int enabled;
};

struct cpu_state {
    unsigned long long next_connection;
    unsigned long long lost;
    unsigned long long perf_overflow;
};

struct tls_event_header {
    unsigned long long timestamp;
    unsigned int thread;
    unsigned int chunk;
    unsigned long long connection;
    unsigned int length;
    unsigned int write;
    unsigned int extended;
    unsigned int reserved;
};

struct tls_event {
    struct tls_event_header header;
    unsigned char payload[MAX_PAYLOAD];
};

#endif
