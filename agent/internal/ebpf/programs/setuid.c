// SPDX-License-Identifier: GPL-2.0
// Vigil eBPF program: trace setuid/setgid for privilege escalation detection.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct priv_event {
    u32 pid;
    u32 old_uid;
    u32 new_uid;
    char comm[TASK_COMM_LEN];
    u64 timestamp;
    u8 event_type;  // 0=setuid, 1=setgid, 2=setns, 3=init_module
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} priv_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e;

    e = bpf_ringbuf_reserve(&priv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->new_uid = (u32)ctx->args[0];
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e;

    e = bpf_ringbuf_reserve(&priv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->new_uid = 0;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 2;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e;

    e = bpf_ringbuf_reserve(&priv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->new_uid = 0;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 3;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
