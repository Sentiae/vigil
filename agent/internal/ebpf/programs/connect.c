// SPDX-License-Identifier: GPL-2.0
// Vigil eBPF program: trace connect syscalls for network connection monitoring.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct connect_event {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 dst_addr;       // IPv4 in network byte order
    u16 dst_port;       // In host byte order
    u16 family;         // AF_INET=2, AF_INET6=10
    u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} connect_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event *e;
    struct sockaddr_in addr = {};

    // Read the sockaddr from userspace
    bpf_probe_read_user(&addr, sizeof(addr), (void *)ctx->args[1]);

    // Only trace IPv4 for now
    if (addr.sin_family != 2) // AF_INET
        return 0;

    e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->dst_addr = addr.sin_addr.s_addr;
    e->dst_port = __builtin_bswap16(addr.sin_port);
    e->family = addr.sin_family;
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
