CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/x86/')
BUILD ?= build
BPF_UAPI ?= /usr/include/$(shell $(CC) -dumpmachine)
LOADER_LIBS ?= -lbpf -lelf

.PHONY: all
all: $(BUILD)/fritap-ebpf-agent

$(BUILD):
	mkdir -p $@

$(BUILD)/capture_ring.bpf.o: capture.bpf.c events.h registers.h | $(BUILD)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) $(BPF_FLAGS) -I$(BPF_UAPI) -c $< -o $@

$(BUILD)/capture_perf.bpf.o: capture.bpf.c events.h registers.h | $(BUILD)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) $(BPF_FLAGS) -I$(BPF_UAPI) -DFRITAP_PERF -mcpu=v1 -c $< -o $@

$(BUILD)/%.skel.h: $(BUILD)/%.bpf.o
	$(BPFTOOL) gen skeleton $< name $* > $@.tmp
	mv $@.tmp $@

$(BUILD)/fritap-ebpf-agent: loader.c events.h perf_order.h $(BUILD)/capture_ring.skel.h $(BUILD)/capture_perf.skel.h
	$(CC) -O2 -Wall -Wextra -Werror $(LOADER_FLAGS) -I$(BUILD) $< -o $@ $(LOADER_LIBS)
