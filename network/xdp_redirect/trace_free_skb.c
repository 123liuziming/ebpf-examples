int trace_free(struct pt_regs *ctx) {
    bpf_trace_printk("Free skb buffer\n\n");
    return 0;
}