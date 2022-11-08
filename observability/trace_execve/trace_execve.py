
# 引入库函数
from bcc import BPF
from bcc.utils import printb

# 加载eBPF代码
b = BPF(src_file="trace_execve.c")

print("%-6s %-16s %-3s %s" % ("PID", "COMM", "RET", "ARGS"))

# 定义性能事件打印函数
def print_event(cpu, data, size):
    # BCC自动根据"struct data_t"生成数据结构
    event = b["events"].event(data)
    printb(b"%-6d %-16s %-3d %-16s" % (event.pid, event.comm, event.retval, event.argv))

# 绑定性能事件映射和输出函数，并从映射中循环读取数据
 
# 1. Perf/Ring Buffer相对于其他种类map(被动轮询)来说，提供专用api，通知应用层事件就绪，减少cpu消耗，提高性能。
# 2. 采用共享内存，节省复制数据开销。
# 3. Perf/Ring Buffer支持传入可变长结构。
# 差异:
# 1. Perf Buffer每个CPU核心一个缓存区，不保证数据顺序(fork exec exit)，会对我们应用层消费数据造成影响。Ring Buffer多CPU共用一个缓存区且内部实现了自旋锁，保证数据顺序。
# 2. Perf Buffer有着两次数据拷贝动作，当空间不足时，效率低下。 Ring Buffer采用先申请内存，再操作形式，提高效率。
# 3. perfbuf 的 buffer size 是在用户态定义的，而 ringbuf 的 size 是在 bpf 程序中预定义的。
# 4. max_entries 的语义， perfbuf 是 buffer 数量(社区推荐设置为cpu个数)，ringbuf 中是单个 buffer 的 size。
# 5. Ring Buffer性能强于Perf Buffer。参考patch 【ringbuf perfbuf 性能对比】
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()