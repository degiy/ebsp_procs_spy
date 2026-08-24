// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "i.h"

#define AF_INET 2
#define AF_INET6 10
 
char LICENSE[] SEC("license") = "Dual BSD/GPL";
char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);  // max 1024 pids to follow at once
	__type(key, u32);
	__type(value, u8);
} current_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 * 16); // 16k entries
} rb SEC(".maps");

const volatile __u32 ref_uid = 0;

static __always_inline u32 check_if_egilible()
{

    /* get UID of process */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid&0xffffffff;          // Effective UID (bits 0-31)

    /* check if it's our user */
    if (uid!=ref_uid)
    {
    //bpf_printk("check eg: uid %d vs %d\n", uid,ref_uid);
        return 0;
    }
    u64 id = bpf_get_current_pid_tgid();
    //u32 tid=id&0xffffffff;
    u32 pid=id>>32;
	/* if it one of our tracked pid */
    u8 *pval= bpf_map_lookup_elem(&current_pids, &pid);
	if ((pval!=0)&&(*pval==1))
        return pid;

    //bpf_printk("check eg: pid %d (tid %d) %p\n", pid,tid,(void*)pval);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    /* get UID of process */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid&0xffffffff;          // Effective UID (bits 0-31)

    /* check if it's our user */
    if (uid!=ref_uid) return 0;
    
	/* get PID */
    u64 id = bpf_get_current_pid_tgid();
    u32 pid=id>>32;

    /*  new process from my user (uid) */
    u8 present=1;
	bpf_map_update_elem(&current_pids, &pid, &present, BPF_ANY);

	/* reserve sample from BPF ringbuf */
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e) return 0;

	e->type = NEW_PROC;
	e->pid = pid;
	bpf_get_current_comm(&e->txt, sizeof(e->txt));

	unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->txt, sizeof(e->txt), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    //bpf_printk("exit\n");
	u32 pid=check_if_egilible();
    if (pid==0) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 rtid=id&0xffffffff;
    u32 rpid=id>>32;
    if (rtid!=rpid) return 0; // dead of a thread, not whole process

    /* ok we managed this process => finished */
    bpf_map_delete_elem(&current_pids, &pid);

	/* reserve sample from BPF ringbuf */
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e) return 0;

	e->type = FIN_PROC;
	e->pid = pid;

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/do_filp_open")
int BPF_PROG(trace_do_filp_open, int dfd, struct filename *pathname, struct open_flags *op)
{
    if (pathname==0 || pathname->name==0) return 0;

    //bpf_printk("filp_open\n");
    u32 pid=check_if_egilible();
    if (pid==0) return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e) return 0;

	e->type = FILE_OPEN;
	e->pid = pid;
    bpf_probe_read_kernel_str(e->txt, sizeof(e->txt), pathname->name);

	bpf_ringbuf_submit(e, 0);

    return 0;
}



SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr)
{

    //bpf_printk("connect\n");
    u32 pid=check_if_egilible();
    if (pid==0) return 0;

	/* reserve sample from BPF ringbuf */
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e) return 0;

	e->type = TCP_CNX;
	e->pid = pid;

    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&(e->ip.dstip), 4, &(sin->sin_addr.s_addr)); // IP dest (be)
    bpf_probe_read_kernel(&(e->ip.dstport), 2 , &(sin->sin_port));         // Port dest (be)

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}


SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *newsk)
{
    if (!newsk) return 0;

    //bpf_printk("accept\n");
    u32 pid=check_if_egilible();
    if (pid==0) return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) return 0;
    
    e->type = TCP_ACC;
    e->pid = pid;

    u16 family = 0;
    BPF_CORE_READ_INTO(&family, newsk, __sk_common.skc_family);
    if (family == AF_INET)
    {
        BPF_CORE_READ_INTO(&(e->ip.srcip), newsk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&(e->ip.dstport), newsk, __sk_common.skc_num);
    }
    else if (family== AF_INET6)
    {
        BPF_CORE_READ_INTO(&(e->ip.dstport), newsk, __sk_common.skc_num);
        u32 check_mapped = BPF_CORE_READ(newsk, __sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);
        if (check_mapped == bpf_htonl(0x0000ffff))
            BPF_CORE_READ_INTO(&(e->ip.srcip), newsk, __sk_common.skc_v6_daddr.in6_u.u6_addr32[3]);
    }
    else
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!msg) return 0;
    //bpf_printk("udp_sendmsg\n");

    u32 pid=check_if_egilible();
    if (pid==0) return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e) return 0;

	e->type = UDP_SND;
	e->pid = pid;

    void *msg_name = BPF_CORE_READ(msg, msg_name);
    if (msg_name)
    {
        e->ip.dstip=  BPF_CORE_READ((struct sockaddr_in *)msg_name, sin_addr.s_addr);
        e->ip.dstport=BPF_CORE_READ((struct sockaddr_in *)msg_name, sin_port);
    }
    else if (sk)
    {
        e->ip.dstip=   BPF_CORE_READ(sk,__sk_common.skc_daddr);
        e->ip.dstport= BPF_CORE_READ(sk,__sk_common.skc_dport);
    }
    else
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(trace_skb_consume_udp, struct sock *sk, struct sk_buff *skb)
{
    if (!skb || !sk)
        return 0;

    //bpf_printk("fe/skb consume udp\n");

    u16 protocol = sk->sk_protocol;
    if (protocol != IPPROTO_UDP) return 0;

    //u32 pid;
    u32 pid=check_if_egilible();
    if (pid==0) return 0;
    //bpf_printk("fe/skb consume udp: eligible %d\n",pid);

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e) return 0;

	e->type = UDP_RCV;
	e->pid = pid;
	// 
	// Extract headers from the sk_buff
	unsigned char *head = NULL;
	u16 network_header = 0;
	u16 transport_header = 0;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

    if (head)
    {
        // First, determine IP version by reading the first byte
        u8 ip_version = 0;
        bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network_header);
        ip_version = (ip_version >> 4) & 0x0F;

		if (ip_version == 4)
        {
			// IPv4
			struct iphdr ip = {0};
			struct udphdr udp = {0};

			// Read IP header to get source address (peer who sent to us)
			if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0)
            {
				__builtin_memcpy(&(e->ip.srcip), &ip.saddr, 4);
				__builtin_memcpy(&(e->ip.dstip), &ip.daddr, 4);
                if ((bpf_ntohl(ip.daddr) & 0xF0000000) == 0xE0000000)
                {
                    e->type = UDP_RCV_MCAST;
                }
			}
            // Read UDP header to get source port
            if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0)
            {
                e->ip.dstport = udp.dest;
            }
        }
    }
    if (!e->ip.srcip)
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    //bpf_printk("fe/skb consume udp: %pI4 => %pI4:%d\n",&(e->ip.srcip),&(e->ip.dstip),__builtin_bswap16(e->ip.dstport));
	bpf_ringbuf_submit(e, 0);
    return 0;
}
