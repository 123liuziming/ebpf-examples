#include <linux/fs.h>
#include <linux/openat2.h>
int hello(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how) {
	if (dfd > 0) {
		bpf_trace_printk("open file %s, dfd is %d", filename, dfd);
	}
	return 0;
}
