/* SPDX-License-Identifier: Apache-2.0 */
/* Metadata-only cgroup connection discovery. No payload access or redirection. */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0
#define AF_INET 2
#define AF_INET6 10
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 1

struct bpf_sock_addr {
    __u32 user_family;
    __u32 user_ip4;
    __u32 user_ip6[4];
    __u32 user_port;
    __u32 family;
    __u32 type;
    __u32 protocol;
};

struct bpf_sock_ops {
    __u32 op;
    __u32 args[4];
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
};

struct pending_connection {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u16 remote_port;
    __u8 remote_address[16];
    char process[16];
};

struct connection_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u16 local_port;
    __u16 remote_port;
    __u16 reserved;
    __u8 local_address[16];
    __u8 remote_address[16];
    char process[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct pending_connection);
} PENDING SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} EVENTS SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;
static long (*bpf_map_delete_elem)(void *, const void *) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *, __u32) = (void *)16;
static __u64 (*bpf_get_socket_cookie)(void *) = (void *)46;
static void *(*bpf_ringbuf_reserve)(void *, __u64, __u64) = (void *)131;
static void (*bpf_ringbuf_submit)(void *, __u64) = (void *)132;

static __u16 network_port(__u32 value) {
    return (__u16)(__builtin_bswap32(value) >> 16);
}

static int remember(void *context, __u16 family, __u32 port, const __u32 *address) {
    __u64 cookie = bpf_get_socket_cookie(context);
    if (!cookie)
        return 1;
    struct pending_connection pending = {};
    pending.timestamp_ns = bpf_ktime_get_ns();
    pending.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    pending.uid = (__u32)bpf_get_current_uid_gid();
    pending.family = family;
    pending.remote_port = network_port(port);
    bpf_get_current_comm(pending.process, sizeof(pending.process));
    if (family == AF_INET)
        __builtin_memcpy(pending.remote_address, address, 4);
    else
        __builtin_memcpy(pending.remote_address, address, 16);
    bpf_map_update_elem(&PENDING, &cookie, &pending, BPF_ANY);
    return 1;
}

SEC("cgroup/connect4")
int lens_connect4(struct bpf_sock_addr *context) {
    return remember(context, AF_INET, context->user_port, &context->user_ip4);
}

SEC("cgroup/connect6")
int lens_connect6(struct bpf_sock_addr *context) {
    return remember(context, AF_INET6, context->user_port, context->user_ip6);
}

SEC("sockops")
int lens_established(struct bpf_sock_ops *context) {
    if (context->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 1;
    __u64 cookie = bpf_get_socket_cookie(context);
    struct pending_connection *pending = bpf_map_lookup_elem(&PENDING, &cookie);
    if (!pending)
        return 1;
    struct connection_event *event =
        bpf_ringbuf_reserve(&EVENTS, sizeof(struct connection_event), 0);
    if (!event) {
        bpf_map_delete_elem(&PENDING, &cookie);
        return 1;
    }
    event->timestamp_ns = pending->timestamp_ns;
    event->pid = pending->pid;
    event->uid = pending->uid;
    event->family = pending->family;
    event->local_port = (__u16)context->local_port;
    event->remote_port = pending->remote_port;
    event->reserved = 0;
    if (pending->family == AF_INET)
        __builtin_memcpy(event->local_address, &context->local_ip4, 4);
    else
        __builtin_memcpy(event->local_address, context->local_ip6, 16);
    __builtin_memcpy(event->remote_address, pending->remote_address, 16);
    __builtin_memcpy(event->process, pending->process, 16);
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&PENDING, &cookie);
    return 1;
}

char LICENSE[] SEC("license") = "Apache-2.0";
