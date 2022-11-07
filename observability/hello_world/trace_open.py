from bcc import BPF
b = BPF(src_file="trace_open.c")
b.attach_kprobe(event="do_sys_openat2", fn_name="hello")
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue

    print("%-18.9f %-20s %-6d %s" % (ts, task, pid, msg))
