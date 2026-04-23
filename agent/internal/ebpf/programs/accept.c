// SPDX-License-Identifier: GPL-2.0
// Vigil eBPF program: trace accept syscalls for inbound connection monitoring.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct accept_event {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 src_addr;       // Remote IPv4 address
    u16 src_port;       // Remote port
    u16 family;
    u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} accept_events SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept(struct trace_event_raw_sys_exit *ctx)
{
    struct accept_event *e;
    int fd = ctx->ret;

    // Only trace successful accepts
    if (fd < 0)
        return 0;

    e = bpf_ringbuf_reserve(&accept_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Note: Reading the peer address from accept's output requires more complex
    // handling (reading from userspace pointer in args[1]). For the initial version,
    // we capture the process context and the connection will be enriched in userspace
    // by reading /proc/net/tcp.
    e->src_addr = 0;
    e->src_port = 0;
    e->family = 2; // AF_INET

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
