//go:build ignore
// +build ignore

#include <stdbool.h>
#include <limits.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

// libbpf defines universal helpers (we don't use it for loading)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TCP_SYNACK_ECECWR (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_ECE | TCP_FLAG_CWR)

// Copied from <netinet/in.h>
#define IPPROTO_TCP 6

// Copied from <netinet/ip.h>
#define	IPTOS_ECN_MASK		0x03
#define	IPTOS_ECN(x)		((x) & IPTOS_ECN_MASK)
#define	IPTOS_ECN_NOT_ECT	0x00
#define	IPTOS_ECN_ECT1		0x01
#define	IPTOS_ECN_ECT0		0x02
#define	IPTOS_ECN_CE		0x03


// See for BPF feature availability by kernel version:
// https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
// Current minimum kernel: v4.18 (for skb_load_bytes_relative)


struct ecn_count {
    __u32 packets_notect;
    __u32 packets_ect1;
    __u32 packets_ect0;
    __u32 packets_ce;
    __u32 synack_ececwr;  // no 8- or 16-bit atomics in eBPF :(
    __u32 packets_ececwr;
    __u32 packets_noececwr;
    __u32 packets_ecenocwr;
};

// We can't use BPF_MAP_TYPE_SK_STORAGE because BPF_PROG_TYPE_SOCKET_FILTER
// programs are not permitted to call bpf_sk_storage_get.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    // max_entries is set dynamically when loading the map
    __type(key, __u64);  // SO_COOKIE
    __type(value, struct ecn_count);
} ecn_store SEC(".maps");


__always_inline bool is_synack_ececwr(struct tcphdr *tp) {
    return (tcp_flag_word(tp) & TCP_SYNACK_ECECWR) == TCP_SYNACK_ECECWR;
}

__always_inline bool is_ececwr(struct tcphdr *tp) {
    return (tcp_flag_word(tp) & (TCP_FLAG_ECE | TCP_FLAG_CWR)) == (TCP_FLAG_ECE | TCP_FLAG_CWR);
}

__always_inline bool is_ecenocwr(struct tcphdr *tp) {
    return (tcp_flag_word(tp) & (TCP_FLAG_ECE | TCP_FLAG_CWR)) == (TCP_FLAG_ECE);
}

__always_inline bool is_noececwr(struct tcphdr *tp) {
    return (tcp_flag_word(tp) & (TCP_FLAG_ECE | TCP_FLAG_CWR)) == (TCP_FLAG_CWR);
}

typedef struct {
    __u8 ecn;
    bool tcp_synack_ececwr;
    bool tcp_ececwr;
    bool tcp_noececwr;
    bool tcp_ecenocwr;
} pkt_info;

static pkt_info parse_ip_packet(struct __sk_buff *skb, bool ipv6) {
    union {
        struct { struct iphdr   net; struct tcphdr tp; } ipv4;
        struct { struct ipv6hdr net; struct tcphdr tp; } ipv6;
    } hdr;
    void *hdrptr = ipv6 ? (void*)&hdr.ipv6 : (void*)&hdr.ipv4;  // noop, but avoids UB
    __u32 hdrlen = ipv6 ? sizeof(hdr.ipv6) : sizeof(hdr.ipv4);

    pkt_info res = { .ecn = -1, .tcp_synack_ececwr = false, .tcp_ececwr = false, .tcp_noececwr = false, .tcp_ecenocwr = false, };
    if (bpf_skb_load_bytes_relative(skb, 0, hdrptr, hdrlen, BPF_HDR_START_NET) != 0)
        return res;

    if (ipv6) {
        // The lower 4 bits of the traffic class (TOS) byte are contained in flow_lbl
        res.ecn = IPTOS_ECN(hdr.ipv6.net.flow_lbl[0] >> 4);
        if (hdr.ipv6.net.nexthdr == IPPROTO_TCP) {
            // Handling (rare) extension headers bloats the BPF code significantly
            res.tcp_synack_ececwr = is_synack_ececwr(&hdr.ipv6.tp);
            res.tcp_ececwr = is_ececwr(&hdr.ipv6.tp);
            res.tcp_noececwr = is_noececwr(&hdr.ipv6.tp);
            res.tcp_ecenocwr = is_ecenocwr(&hdr.ipv6.tp);
        }
    } else {
        res.ecn = IPTOS_ECN(hdr.ipv4.net.tos);
        if (hdr.ipv4.net.protocol == IPPROTO_TCP) {
            res.tcp_synack_ececwr = is_synack_ececwr(&hdr.ipv4.tp);
            res.tcp_ececwr = is_ececwr(&hdr.ipv4.tp);
            res.tcp_noececwr = is_noececwr(&hdr.ipv4.tp);
            res.tcp_ecenocwr = is_ecenocwr(&hdr.ipv4.tp);
        }
    }
    return res;
}


SEC("socket")
int count_ecn(struct __sk_buff *skb) {
    __u64 sockid = bpf_get_socket_cookie(skb);
    if (sockid == 0)
        goto pass_full;

    pkt_info pkt;
    bool ipv6 = false;
    switch (skb->protocol) {
        // skb->protocol is stored in network byte order
        case bpf_htons(ETH_P_IPV6):
            ipv6 = true;
            // FALLTHROUGH
        case bpf_htons(ETH_P_IP):
            pkt = parse_ip_packet(skb, ipv6);
            break;
        default:
            goto pass_full;
    }
    if (pkt.ecn > IPTOS_ECN_CE)
        goto pass_full;

    struct ecn_count *ctr = bpf_map_lookup_elem(&ecn_store, &sockid);
    if (ctr) {
        // Shortcut for select (ecn) {...}
        __u32 *f = (&ctr->packets_notect) + pkt.ecn;
        __atomic_fetch_add(f, 1, __ATOMIC_RELAXED);
        if (pkt.tcp_synack_ececwr)
            __atomic_fetch_add(&ctr->synack_ececwr, 1, __ATOMIC_RELAXED);
        if (pkt.tcp_ececwr)
            __atomic_fetch_add(&ctr->packets_ececwr, 1, __ATOMIC_RELAXED);
        if (pkt.tcp_noececwr)
            __atomic_fetch_add(&ctr->packets_noececwr, 1, __ATOMIC_RELAXED);
        if (pkt.tcp_ecenocwr)
            __atomic_fetch_add(&ctr->packets_ecenocwr, 1, __ATOMIC_RELAXED);
    } else {
        struct ecn_count new_ctr = { .synack_ececwr = pkt.tcp_synack_ececwr,
            .packets_ececwr = pkt.tcp_ececwr, .packets_noececwr = pkt.tcp_noececwr,
            .packets_ecenocwr = pkt.tcp_ecenocwr};
        *((&new_ctr.packets_notect) + pkt.ecn) = 1;
        bpf_map_update_elem(&ecn_store, &sockid, &new_ctr, BPF_NOEXIST);
        // ignore insert error: not much we can do here
    }

pass_full:
    // Don't actually filter anything
    return INT_MAX;
}
