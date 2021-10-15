#pragma once

// NOTE: this file is included by both the user-space program and the kernel eBPF program
// since the eBPF program relies on including vmlinux, do no include linux system headers in here.
// If any such headers are required, included them in user space before including this file.


#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define DNS_MAX_LEN 84

// event opcodes
#define OP_PROCESS_EXEC 0x01
#define OP_PROCESS_EXIT 0x02
#define OP_SOCK_STATE_CHANGE_V4 0x03
#define OP_DNS_LOOKUP_V4 0x04

// event header
typedef struct fm_header {
	unsigned short int  op_code;	// 0x0, 2
	unsigned short int  pad;	    // 0x2, 2
	pid_t pid;						// 0x4, 4
} fm_header_t;						// 0x8

// process exec event
typedef struct fm_exec {
	fm_header_t hdr;
	pid_t ppid;
	char comm[TASK_COMM_LEN];			// should be converted to size + non null terminated string
	char filename[MAX_FILENAME_LEN];    // should be converted to size + non-null terminated string
} fm_exec_t;

// process exit event
typedef struct fm_exit {
	fm_header_t hdr;
	int ppid;
	unsigned int exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
} fm_exit_t;

// socket state change event
typedef struct fm_sock_state_change_v4 {
	fm_header_t hdr;
	unsigned long long sk;
	unsigned int net_ns;
	unsigned int saddr;
	unsigned int daddr;
	unsigned short int sport;
	unsigned short int dport;
	int old_state;
	int new_state;
} fm_sock_state_change_v4_t;

// dns lookup event
typedef struct fm_dns_lookup_v4 {
	fm_header_t hdr;
	char question[DNS_MAX_LEN];
	char cname[DNS_MAX_LEN];
	unsigned int ip;
} fm_dns_lookup_v4_t;
