#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>

BPF_CPUMAP(cpumap, __MAX_CPU__);
BPF_ARRAY(dest, uint32_t, 1);
BPF_PERCPU_ARRAY(rxcnt, long, 1);

int xdp_redirect_cpu(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    uint32_t key = 0;
    long *value;
    uint32_t *cpu;
    uint64_t nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return XDP_DROP;

    cpu = dest.lookup(&key);
    if (!cpu)
        return XDP_DROP;

    value = rxcnt.lookup(&key);
    if (value)
        *value += 1;

    return cpumap.redirect_map(*cpu, 0);
}