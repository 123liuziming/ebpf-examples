#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct stack_key_t {
  int pid;
  char name[16];
  int user_stack;
  int kernel_stack;
};

BPF_STACK_TRACE(stack_traces, 16384);
BPF_HASH(counts, struct stack_key_t, uint64_t);

int on_tcp_send(struct pt_regs *ctx) {
  struct stack_key_t key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&key.name, sizeof(key.name));
  key.kernel_stack = stack_traces.get_stackid(ctx, 0);
  key.user_stack = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

  u64 zero = 0, *val;
  val = counts.lookup_or_try_init(&key, &zero);
  if (val) {
    (*val)++;
  }

  return 0;
}