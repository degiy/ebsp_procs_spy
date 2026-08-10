/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __I_H
#define __I_H

#define MAX_STR 200

typedef enum 
{
NEW_PROC,
FIN_PROC,
FILE_OPEN,
UDP_SND,
UDP_RCV,
TCP_CNX,
TCP_ACC
} event_type;

struct event {
    event_type type;
	__u32 pid;
    union {
        struct {
        __u32 srcip;
        __u32 dstip;
        __u16 srcport;
        __u16 dstport;
        } ip;
        char txt[MAX_STR];
    };
};

#endif /* __I_H */
