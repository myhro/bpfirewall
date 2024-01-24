#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// From include/uapi/linux/if_ether.h
int ETH_P_IP = 0x0800;

struct tcphdr *tcp_header(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *) eth + sizeof(struct ethhdr) > data_end) {
        return NULL;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return NULL;
    }

    struct iphdr *iph = (void *) eth + sizeof(struct ethhdr);
    if ((void *) iph + sizeof(struct iphdr) > data_end) {
        return NULL;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return NULL;
    }

    struct tcphdr *tcph = (void *) iph + sizeof(struct iphdr);
    if ((void *) tcph + sizeof(struct tcphdr) > data_end) {
        return NULL;
    }

    return tcph;
}
