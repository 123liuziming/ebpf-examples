from bcc import BPF
import os
import atexit
import sys
import time

bpf = BPF(src_file="socket_redirect.c")
func_sock_ops = bpf.load_func("bpf_sockhash", bpf.SOCK_OPS)
func_sock_redir = bpf.load_func("bpf_redir", bpf.SK_MSG)
fd = os.open("/sys/fs/cgroup", os.O_RDONLY)
map_fd = bpf['sock_hash'].get_fd()
bpf.attach_func(func_sock_ops, fd, BPF.CGROUP_SOCK_OPS)
bpf.attach_func(func_sock_redir, map_fd, BPF.SK_MSG_VERDICT)

def detach_all():
    bpf.detach_func(func_sock_ops, fd, BPF.CGROUP_SOCK_OPS)
    bpf.detach_func(func_sock_redir, map_fd, BPF.SK_MSG_VERDICT)
    print("Detaching...")

atexit.register(detach_all)

while True:
    try:
        bpf.trace_print()
        sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)