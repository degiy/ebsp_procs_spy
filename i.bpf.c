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
    __uint(max_entries, 1024); // no more of 1024 IPM
    __type(key, struct sock *);
    __type(value, u32); // IP Multicast
} mcast_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);  // max 128 pids to follow at once
	__type(key, u32);
	__type(value, u8);
} current_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 * 16); // 16k entries
} rb SEC(".maps");

const volatile __u32 ref_uid = 0;

int check_if_egilible()
{
    u64 id;
    u32 pid;
    u8 *pid_find;

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

    return pid;
}

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
	u32 pid;

    pid=check_if_egilible();
    if (pid==0) return 0;

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
    u32 pid;
	struct event *e;

    if (pathname==0 || pathname->name==0)
        return 0;

    pid=check_if_egilible();
    if (pid==0) return 0;

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

// to put a tag on mcast flow to recover ipm group on the user level
SEC("kprobe/udp_queue_rcv_skb")
int BPF_KPROBE(udp_queue_rcv_skb, struct sock *sk, struct sk_buff *skb) {
    if (!sk || !skb) return 0;

    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr *iph = (struct iphdr *)(head + network_header);

    u32 daddr = BPF_CORE_READ(iph, daddr);

    // Filtrer pour garder uniquement le multicast IPv4 (224.0.0.0/4)
    if ((daddr & 0x000000F0) == 0x000000E0) {
        bpf_map_update_elem(&mcast_sockets, &sk, &daddr, BPF_ANY);
    }

    return 0;
}

// can be use for udp ucast or mcast flow
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_exit, struct sock *sk, struct msghdr *msg, \
             size_t len, int flags, int *addr_len, int ret)
{
	struct event *e;
    u32 mcast_daddr=0;
    u32 *mcast_ip; 
    u32 pid;

    if (!sk) return 0;
    // check wether it's mcast or not (because we caught all mcast flow form all user/pids)
    mcast_ip = bpf_map_lookup_elem(&mcast_sockets, &sk);
    if (mcast_ip)
    {
        mcast_daddr = *mcast_ip;
        // map cleaning (even if not for us)
        bpf_map_delete_elem(&mcast_sockets, &sk);
    }

    if (ret < 0 || !msg || !msg->msg_name ) return 0;

    pid=check_if_egilible();
    if (pid==0) return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->type = UDP_RCV;
	e->pid = pid;

    struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
    e->ip.srcip=BPF_CORE_READ(sin, sin_addr.s_addr);
    e->ip.dstport  = BPF_CORE_READ(sk, __sk_common.skc_num);

    // mcast handling
    e->ip.dstip=mcast_daddr;

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    u32 pid;
	struct event *e;
    void *msg_name;

    if (!msg) return 0;

    pid=check_if_egilible();
    if (pid==0) return 0;


	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = UDP_SND;
	e->pid = pid;

    // secure read of msg_name
    msg_name = BPF_CORE_READ(msg, msg_name);
    if (msg_name)
    {
        // mcast (no socket bind)
        e->ip.dstip=  BPF_CORE_READ((struct sockaddr_in *)msg_name, sin_addr.s_addr);
        e->ip.dstport=BPF_CORE_READ((struct sockaddr_in *)msg_name, sin_port);
    }
    else if (sk)
    {
        // connected socket
        e->ip.dstip=   BPF_CORE_READ(sk,__sk_common.skc_daddr);
        e->ip.dstport= BPF_CORE_READ(sk,__sk_common.skc_dport);
    }
    else {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr)
{
    u32 pid;
	struct event *e;

    pid=check_if_egilible();
    if (pid==0) return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = TCP_CNX;
	e->pid = pid;

    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&(e->ip.dstip), 4, &(sin->sin_addr.s_addr)); // IP dest (be)
    bpf_probe_read_kernel(&(e->ip.dstport), 2 , &(sin->sin_port));         // Port dest (be)

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

#define AF_INET 2

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *newsk)
{
    u32 pid;
	struct event *e;
    u16 family = 0;

    if (!newsk)
        return 0;

    pid=check_if_egilible();
    if (pid==0) return 0;

    // Filter IPv4 only
    BPF_CORE_READ_INTO(&family, newsk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
    
	e->type = TCP_ACC;
	e->pid = pid;

    BPF_CORE_READ_INTO(&(e->ip.srcip), newsk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&(e->ip.dstport), newsk, __sk_common.skc_num);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
