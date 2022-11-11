from bcc import BPF
import sys

# load BPF program
b = BPF(src_file = "trace_free_skb.c")
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_free")

# process event
start = 0
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        if task == b'curl':
            print(task, pid, cpu, msg)
    except KeyboardInterrupt:
        sys.exit(0)