#include <net/sock.h>

#define MAX_SOCK_OPS_MAP_ENTRIES 1024


typedef struct sock_key {
    u32 remote_ip4;
    u32 local_ip4;
    u32 remote_port;
    u32 local_port;
} sk_key;
BPF_SOCKHASH(skh, sk_key, MAX_SOCK_OPS_MAP_ENTRIES);

// 套接字映射更新操作
// BPF_PROG_TYPE_SOCK_OPS是在TCP协议EVENT(比如链接建立，连接断开等)发生时的BPF钩子
int bpf_sockhash(struct bpf_sock_ops *skops) {
    // 只支持IPV4
    if (skops->family != AF_INET) {
        return 0;
    }
    // 将建立的连接添加到socket_map里，如果此监听到的TCP事件不是连接事件，则跳过
    // BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB 主动建立连接
    // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 被动建立连接
    if (skops-> op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return 0;
    }
    struct sock_key skk = {
        .remote_ip4 = bpf_ntohl(skops->remote_ip4),
        .local_ip4  = skops->local_ip4,
        .local_port = skops->local_port,
        // 将网络字节序转为主机字节序
        .remote_port = bpf_ntohl(skops->remote_port),
    };
     // 添加到sock_hash中
     int ret = skh.sock_hash_update(skops, &skk, BPF_NOEXIST);
    if (ret) {
        // bpf_trace_printk("bpf_sock_hash_update() failed. %d", -ret);
        return 0;
    }
    //bpf_trace_printk("Connection has been established: %u <--> %u", skops->local_ip4, skops->remote_ip4);
    return 0;
}

int bpf_redir(struct sk_msg_md *msg) {
    // if (msg->family != AF_INET) {
    //     return SK_PASS;
    // }
    // if (msg->remote_ip4 != msg->local_ip4) {
    //     return SK_PASS;
    // }
    // 将local和remote进行反向
    struct sock_key skk = {
        .remote_ip4 = bpf_ntohl(msg->local_ip4),
        .local_ip4  = msg->remote_ip4,
        .local_port = bpf_ntohl(msg->remote_port),
        .remote_port = msg->local_port,
    };
    // 将入口流量转发
    int ret = skh.msg_redirect_hash(msg, &skk, BPF_F_INGRESS);
    //bpf_trace_printk("Socket has been redirected: %d <--> %d", msg->remote_ip4, msg->local_ip4);
    return ret;
}

