BINARY = firewall
BPF_OBJ := firewall.bpf.o
IFACE ?= eth0
MAP_FILE := /sys/fs/bpf/ports
PROG_FILE := /sys/fs/bpf/firewall

.PHONY: $(BINARY) $(BPF_OBJ)

attach:
	sudo bpftool net attach xdp name firewall dev $(IFACE)

clean:
	rm -f *.o firewall vmlinux.h

detach:
	sudo bpftool net detach xdp dev $(IFACE)

firewall:
	gcc firewall.c -o $(BINARY) -lbpf

firewall.bpf.o:
	clang -target bpf \
		-D __TARGET_ARCH_x86 \
		-I /usr/include/x86_64-linux-gnu/ \
		-g -O2 -c firewall.bpf.c -o $(BPF_OBJ)
	llvm-strip-14 -g $(BPF_OBJ)

load: prog-load pin attach

pin:
	sudo bpftool map pin name ports $(MAP_FILE)

prog-load:
	sudo bpftool prog load $(BPF_OBJ) $(PROG_FILE)

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

unload: detach unpin

unpin:
	sudo rm -f $(PROG_FILE) $(MAP_FILE)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
