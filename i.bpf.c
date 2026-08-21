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

struct udpshare {
    u32 saddr;
    u32 daddr;
    u16 dport;
    u16 len;
} ;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024*16);  // max 128 pids to follow at once
	__type(key, u64);
	__type(value, struct udpshare);
} current_udp SEC(".maps");

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
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
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
	struct event *e;
	u32 pid;

    //bpf_printk("exit\n");
    pid=check_if_egilible();
    if (pid==0) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 rtid=id&0xffffffff;
    u32 rpid=id>>32;
    if (rtid!=rpid) return 0; // dead of a thread, not whole process

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

    if (pathname==0 || pathname->name==0) return 0;

    //bpf_printk("filp_open\n");
    pid=check_if_egilible();
    if (pid==0) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = FILE_OPEN;
	e->pid = pid;
    bpf_probe_read_kernel_str(e->txt, sizeof(e->txt), pathname->name);

	bpf_ringbuf_submit(e, 0);

    return 0;
}



SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr)
{
    u32 pid;
	struct event *e;

    //bpf_printk("connect\n");
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


SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *newsk)
{
    if (!newsk) return 0;

    //bpf_printk("accept\n");
    u32 pid=check_if_egilible();
    if (pid==0) return 0;

	struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
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
    u32 pid;
	struct event *e;
    void *msg_name;

    if (!msg) return 0;
    //bpf_printk("udp_sendmsg\n");

    pid=check_if_egilible();
    if (pid==0) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->type = UDP_SND;
	e->pid = pid;

    msg_name = BPF_CORE_READ(msg, msg_name);
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

static __always_inline unsigned char *get_ip_header(struct sk_buff *skb)
{
    unsigned char *head = skb->head;
    u16 net_off = skb->network_header;
    u16 mac_off = skb->mac_header;
    u16 trans_off = skb->transport_header;

    // 1. Cas nominal : network_header est valide
    if (net_off < 0x0fff) {
        return head + net_off;
    }

    // 2. Repli via mac_header (Offset L2 + 14 octets Ethernet)
    if (mac_off < 0x0fff) {
        return head + mac_off + 14; // 14 = sizeof(struct ethhdr)
    }

    // 3. Repli via transport_header (On remonte de 20 octets avant le header UDP)
    if (trans_off < 0x0fff && trans_off >= sizeof(struct iphdr)) {
        return head + trans_off - sizeof(struct iphdr);
    }

    return NULL;
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
	struct event *e;
    u32 pid=check_if_egilible();
    if (pid==0) return 0;
    bpf_printk("fe/skb consume udp: eligible %d\n",pid);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->type = UDP_RCV;
	e->pid = pid;

    u16 family = sk->__sk_common.skc_family;

    unsigned char *ip_hdr = get_ip_header(skb);
    if (!ip_hdr)
    {
            bpf_ringbuf_discard(e, 0);
            return 0;
    }

    if (family == AF_INET)
    {
        struct iphdr iph;
        if (bpf_probe_read_kernel(&iph, sizeof(iph), ip_hdr) < 0)
        {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        // src IP
        e->ip.srcip = iph.saddr;
        if ((bpf_ntohl(iph.daddr) & 0xF0000000) == 0xE0000000)
        {
            // mcast, need dst IP
            e->ip.dstip = iph.daddr;
        }
        else
        {
            e->ip.dstip = 0;
        }
        // UDP
        unsigned char *udphp = ip_hdr + (iph.ihl * 4);
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), udphp) < 0)
        {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->ip.dstport = udph.dest;
    }
    else
    {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_printk("fe/skb consume udp: %pI4 => %pI4:%d\n",&(e->ip.srcip),&(e->ip.dstip),__builtin_bswap16(e->ip.dstport));
	bpf_ringbuf_submit(e, 0);
    return 0;
}

// Capture the sk_buff when __skb_recv_udp returns it
SEC("kretprobe/__skb_recv_udp")
int BPF_KRETPROBE(skb_recv_udp_exit, struct sk_buff *skb)
{
	if (!skb)
		return 0;
    //bpf_printk("skb_recv_udp_exit\n");

    u32 pid;
	struct event *e;
    pid=check_if_egilible();
    if (pid==0) return 0;
    bpf_printk("skb_recv_udp_exit: eligible %d\n",pid);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->type = UDP_RCV;
	e->pid = pid;

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
			}
            // Read UDP header to get source port
            if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0)
            {
                e->ip.dstport = udp.dest;
            }

        }
        else if (ip_version == 6)
        {
            // IPv6
            struct udphdr udp = {0};
            e->ip.srcip=0x6060606;
            e->ip.dstip=0x42424242;
            // Read UDP header to get source port
            if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0)
            {
                e->ip.dstport = udp.dest;
            }
        }
    }
    bpf_printk("skb_rev_udp_exit: udp: %pI4 => %pI4:%d\n",&(e->ip.srcip),&(e->ip.dstip),__builtin_bswap16(e->ip.dstport));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_queue_rcv_one_skb")
int BPF_KPROBE(udp_queue_rcv_one_skb_entry, struct sock *sk, struct sk_buff *skb)
{
	if (!sk || !skb)
		return 0;

	// Extract headers from skb
	unsigned char *head = NULL;
	u16 network_header = 0;
	u16 transport_header = 0;

    u32 ips,ipd;
    u16 dstp,len;

    ips=0x01010101;
    ipd=0x02020202;
    dstp=12345;
    len=12345;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	if (!head) return 0;

	// Read IP and UDP headers to get peer address and payload length
	struct iphdr ip = {0};
	struct udphdr udp = {0};

	if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
		__builtin_memcpy(&ips, &ip.saddr, 4);
		__builtin_memcpy(&ipd, &ip.daddr, 4);
	}

	if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
		dstp = __builtin_bswap16(udp.source);
		u16 udp_total_len = __builtin_bswap16(udp.len);
		len = udp_total_len > sizeof(struct udphdr)
			? udp_total_len - sizeof(struct udphdr)
			: 0;
	}
    struct udpshare m={ips,ipd,dstp,len};
	u64 socket_cookie = (u64)sk;
    bpf_map_update_elem(&current_udp, &socket_cookie, &m, BPF_ANY);

    bpf_printk("udp_queue_rcv_one_skb: %pI4 -> %pI4:%d (%d)\n", &ips, &ipd,dstp,len);
    return 0;
}
