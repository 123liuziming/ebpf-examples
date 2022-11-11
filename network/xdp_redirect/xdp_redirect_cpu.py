from bcc import BPF
import time
import sys
from multiprocessing import cpu_count
import ctypes as ct

flags = BPF.XDP_FLAGS_SKB_MODE
def usage():
    print("Usage: {0} <in ifdev> <CPU id>".format(sys.argv[0]))
    print("e.g.: {0} eth0 2\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 3:
    usage()

in_if = sys.argv[1]
cpu_id = int(sys.argv[2])

max_cpu = cpu_count()
if (cpu_id > max_cpu):
    print("Invalid CPU id")
    exit(1)

# load BPF program
b = BPF(src_file="xdp_redirect_cpu.c", cflags=["-w", "-D__MAX_CPU__=%u" % max_cpu], debug=0)

dest = b.get_table("dest")
dest[0] = ct.c_uint32(cpu_id)

cpumap = b.get_table("cpumap")
cpumap[cpu_id] = ct.c_uint32(16384)

in_fn = b.load_func("xdp_redirect_cpu", BPF.XDP)
b.attach_xdp(in_if, in_fn, flags)

rxcnt = b.get_table("rxcnt")
prev = 0
while 1:
    try:
        val = rxcnt.sum(0).value
        if val:
            delta = val - prev
            prev = val
            print("{} pkt/s to CPU {}".format(delta, cpu_id))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(in_if, flags)
