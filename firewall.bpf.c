#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "network.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u16);
    __type(value, u8);
} ports SEC(".maps");

bool blocked(u16 dest) {
    void *p = bpf_map_lookup_elem(&ports, &dest);
    if (p == NULL) {
        return false;
    }
    return true;
}

SEC("xdp")
int firewall(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;

    struct tcphdr *tcph = tcp_header(data, data_end);
    if (tcph == NULL) {
        return XDP_PASS;
    }

    u16 dest = bpf_ntohs(tcph->dest);
    if (blocked(dest)) {
        bpf_printk("Blocked port: %d", dest);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
