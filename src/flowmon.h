#pragma once

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define OP_PROCESS_EXEC 0x01
#define OP_PROCESS_EXIT 0x02
#define OP_SOCK_STATE_CHANGE_V4 0x03

typedef struct fm_header {
	unsigned short int  op_code;	// 0x0, 2
	unsigned short int  pad;	    // 0x2, 2
	pid_t pid;						// 0x4, 4
} fm_header_t;					// 0x8

typedef struct fm_exec {
	fm_header_t hdr;
	pid_t ppid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
} fm_exec_t;

typedef struct fm_exit {
	fm_header_t hdr;
	int ppid;
	unsigned int exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
} fm_exit_t;

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