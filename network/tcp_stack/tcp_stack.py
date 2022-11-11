from bcc import BPF
bpf = BPF(src_file="tcp_stack.c")

bpf.attach_krobe("tcp_sendmsg", )