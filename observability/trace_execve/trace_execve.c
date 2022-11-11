// ls /sys/kernel/debug/tracing/events 查看所有挂载点
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE 64
#define TOTAL_MAX_ARGS 5
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

// perf缓存
BPF_PERF_OUTPUT(events);

// ebpf map, key为进程id
struct data_t {
	u32 pid;
	char comm[TASK_COMM_LEN];
	int retval;
	unsigned int args_size;
	char argv[FULL_MAX_ARGS_ARR];
};
BPF_HASH(tasks, u32, struct data_t);

// 读取用户空间字符串
static int __bpf_read_arg_str(struct data_t *data, const char *ptr)
{
	if (data->args_size > LAST_ARG) {
		return -1;
	}
	int ret = bpf_probe_read_user_str(&data->argv[data->args_size], ARGSIZE,
					  (void *)ptr);
	if (ret > ARGSIZE || ret < 0) {
		return -1;
	}
	data->args_size += (ret - 1);
	return 0;
}

// 进入sys_execve
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
	unsigned int ret = 0;
	const char **argv = (const char **)(args->argv);
	struct data_t data = { };
	u32 pid = bpf_get_current_pid_tgid();
	data.pid = pid;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	// 读取文件名
	if (__bpf_read_arg_str(&data, (const char *)argv[0]) < 0) {
		goto out;
	}
	// 获取其他参数
	// ebpf的循环需要使用宏展开
#pragma unroll
	for (int i = 1; i < TOTAL_MAX_ARGS; i++) {
		if (__bpf_read_arg_str(&data, (const char *)argv[i]) < 0) {
			goto out;
		}
	}
 out:
	// 存储到map结构中
	tasks.update(&pid, &data);
	return 0;
}

// 字符串比较
static int cmp_str(const char* s1, const char* s2) {
	if (!s1 || !s2) {
		return -1;
	}
	if ((*s1 != '\0') && (*s2 == *s2)) {
		++s1;
		++s2;
	}
	if (*s1 > *s2) {
		return 1;
	} else if (*s1 < *s2) {
		return -1;
	} else {
		return 0;
	}
}

// 退出sys_execve
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct data_t *data = tasks.lookup(&pid);
	if (data != NULL) {
		data->retval = args->ret;
		if (!cmp_str("ls", data->comm)) {
			events.perf_submit(args, data, sizeof(struct data_t));
		}
		tasks.delete(&pid);
	}
	return 0;
}