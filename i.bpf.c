// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "i.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u32);
	__type(value, u8);
} current_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile __u32 ref_uid = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	u32 pid;
    const u8 present=1;

    /* get UID of process */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;          // Effective UID (bits 0-31)

    /* check if it's our user */
    if (uid!=ref_uid)
        return 0;
    
	/* get PID */
	pid = ctx->pid;

    /* is this new process from my user (uid) */
	bpf_map_update_elem(&current_pids, &pid, &present, BPF_ANY);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->type = NEW_PROC;
	e->pid = pid;
	bpf_get_current_comm(&e->txt, sizeof(e->txt));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->txt, sizeof(e->txt), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct event *e;
    u64 id;
	u32 pid, tid;
    u8 *pid_find;

    /* get UID of process */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;          // Effective UID (bits 0-31)

    /* check if it's our user */
    if (uid!=ref_uid)
        return 0;

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if it one of our tracked pid */
	pid_find = bpf_map_lookup_elem(&current_pids, &pid);
	if ((pid_find==0) || (*pid_find!=1))
        return 0;

    /* ok we managed this process => finished */
    bpf_map_delete_elem(&current_pids, &pid);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = FIN_PROC;
	e->pid = pid;

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/do_filp_open")
int BPF_PROG(trace_do_filp_open, int dfd, struct filename *pathname, struct open_flags *op)
{
    u64 id;
    u32 pid;
    u8 *pid_find;
	struct event *e;

    /* get UID of process */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;          // Effective UID (bits 0-31)

    /* check if it's our user */
    if (uid!=ref_uid)
        return 0;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;

	/* if it one of our tracked pid */
	pid_find = bpf_map_lookup_elem(&current_pids, &pid);
	if ((pid_find==0) || (*pid_find!=1))
        return 0;

    if (pathname==0 || pathname->name==0)
        return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = FILE_OPEN;
	e->pid = pid;
    bpf_probe_read_kernel_str(e->txt, sizeof(e->txt), pathname->name);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

#define AF_INET 2

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg, struct sock *sk)
{
    u64 id;
    u32 pid;
    u8 *pid_find;
	struct event *e;

    /* get UID of process */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;          // Effective UID (bits 0-31)

    /* check if it's our user */
    if (uid!=ref_uid)
        return 0;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;

	/* if it one of our tracked pid */
	pid_find = bpf_map_lookup_elem(&current_pids, &pid);
	if ((pid_find==0) || (*pid_find!=1))
        return 0;

    /* exit if not IPv4 */
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
        return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = UDP_RCV;
	e->pid = pid;
    e->ip.srcip    = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->ip.dstip    = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->ip.srcport  = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->ip.dstport  = BPF_CORE_READ(sk, __sk_common.skc_num);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
    
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk)
{
    u64 id;
    u32 pid;
    u8 *pid_find;
	struct event *e;

    /* get UID of process */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;          // Effective UID (bits 0-31)

    /* check if it's our user */
    if (uid!=ref_uid)
        return 0;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;

	/* if it one of our tracked pid */
	pid_find = bpf_map_lookup_elem(&current_pids, &pid);
	if ((pid_find==0) || (*pid_find!=1))
        return 0;

    /* exit if not IPv4 */
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
        return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = UDP_SND;
	e->pid = pid;
    e->ip.dstip    = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->ip.srcip    = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->ip.dstport  = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->ip.srcport  = BPF_CORE_READ(sk, __sk_common.skc_num);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
