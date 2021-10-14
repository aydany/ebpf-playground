#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "flowmon.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);					// thread id
	__type(value, struct sock *);		// socket
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);					// process id
	__type(value, u64);					// process start time
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	fm_exec_t *e;
	pid_t pid;
	u64 ts;

	// record the process start time
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	// reserve space in the buffer
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();

	// fill in the process details
	e->hdr.op_code = OP_PROCESS_EXEC;
	e->hdr.pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void*)ctx + fname_off);

	// send it to userspace
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	fm_exit_t *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	// ignore thread exit
	if (pid != tid) {
		return 0;
	}

	// lookup the previously stashed process start time
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts) {
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	}
	// delete the table entry: isn't there a single lookup and delete call instead,
	// or a delete that takes the returned value pointer to avoid doing another lookup?
	bpf_map_delete_elem(&exec_start, &pid);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();

	e->hdr.op_code = OP_PROCESS_EXIT;
	e->hdr.pid = pid;
	e->duration_ns = duration_ns;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// struct trace_event_raw_inet_sock_set_state {
// 	struct trace_entry ent;
// 	const void *skaddr;
// 	int oldstate;
// 	int newstate;
// 	__u16 sport;
// 	__u16 dport;
// 	__u16 family;
// 	__u16 protocol;
// 	__u8 saddr[4];
// 	__u8 daddr[4];
// 	__u8 saddr_v6[16];
// 	__u8 daddr_v6[16];
// 	char __data[0];
// };


SEC("tp/sock/inet_sock_set_state")
int trace_sock_set_state(struct trace_event_raw_inet_sock_set_state * ctx) {
	if (ctx->protocol != IPPROTO_TCP) {
		return 0;
	}

 	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct sock *sk = (struct sock *)ctx->skaddr;

	if (ctx->family == 2 /*AF_INET*/) {
		// IPv4
		fm_sock_state_change_v4_t* e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e) {
			return 0;
		}


		e->hdr.op_code = OP_SOCK_STATE_CHANGE_V4;
		e->hdr.pid = pid;
		e->sk = (u64)ctx->skaddr;
		e->net_ns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		__builtin_memcpy(&e->saddr, ctx->saddr, sizeof(e->saddr));
		__builtin_memcpy(&e->daddr, ctx->daddr, sizeof(e->daddr));
		e->sport = ctx->sport;
		e->dport = ctx->dport;
		e->old_state = ctx->oldstate;
		e->new_state = ctx->newstate;

		bpf_ringbuf_submit(e, 0);

		return 0;
	} 

	// IPv6

	return 0;
}

/*




















SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	if (tid == 0) {
		return 0;
	}

	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
};

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret)
{
	u64 tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)tgid;
	pid_t pid = tgid >> 32;

	struct sock **sockpp;
	struct lookup *lookup;
	u32 saddr, daddr;
	u16 sport, dport;

 	if (tid == 0) {
		 return 0;
	 }

 	if (ret != 0) {
		 bpf_printk("Could not connect: ret=%d\n", ret);
		 goto cleanup;
	}

	sockpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!sockpp) {
		return 0;
	}

 	ip = BPF_CORE_READ(*sockpp, __sk_common.skc_daddr);


// 	lookup = bpf_map_lookup_elem(&hostnames, &ip);
// 	if (!lookup) {
// 		event.tag = IP;
// 		memcpy(&event.ip, &ip, sizeof(event.ip));
// 	} else {
// 		event.tag = HOSTNAME;
// 		memcpy(&event.hostname, &lookup->c, sizeof(lookup->c));
// 		bpf_map_delete_elem(&hostnames, &ip);
// 	}
// 	//ctx is implied in the signature macro
// 	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
// cleanup:
// 	bpf_map_delete_elem(&sockets, &tid);
// 	return 0;
}
*/