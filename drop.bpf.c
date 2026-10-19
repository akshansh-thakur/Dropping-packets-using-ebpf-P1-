
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#define DEFAULT_PORT 4040



struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} blocked_port SEC(".maps");



SEC("xdp")
int drop_tcp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

     struct ethhdr *eth = data;

    if ((void *)(eth + 1) > end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP ||
    ip->ihl < 5 || ip->ihl > 15)
    return XDP_PASS;

    

void *ip_end = (void *)ip + ip->ihl * 4;

if (ip_end > end)
    return XDP_PASS;

struct tcphdr *tcp = ip_end;



    if ((void *)(tcp + 1) > end)
        return XDP_PASS;


        
    __u32 key = 0;
    __u32 *port = bpf_map_lookup_elem(&blocked_port, &key);

    

    if (port && bpf_ntohs(tcp->dest) == *port)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
