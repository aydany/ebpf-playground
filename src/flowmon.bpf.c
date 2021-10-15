// eEBF programs based on CO:RE should include vmlinux.h and should
// not include system header files, since that will result in redefining some types.
// The BPF headers are safe to include.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "flowmon.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2

// taken from tracee.
// question: if we do foo = READ_KERN(ptr), does the compiler avoid the copy
// when assigneing _val to foo?
#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_core_read(&_val, sizeof(_val), &ptr);     \
                          _val;											\
						})

/* Copied from: include/netdb.h */
struct addrinfo {
	int ai_flags; /* Input flags.  */
	int ai_family; /* Protocol family for socket.  */
	int ai_socktype; /* Socket type.  */
	int ai_protocol; /* Protocol for socket.  */
	u32 ai_addrlen; /* Length of socket address.  */
	struct sockaddr *ai_addr; /* Socket address for socket.  */
	char *ai_canonname; /* Canonical name for service location.  */
	struct addrinfo *ai_next; /* Pointer to next in list.  */
};

// temporary struct for DNS lookup tracking
struct lookup {
	char question[DNS_MAX_LEN];
	struct addrinfo **results;
};

// hash table for DNS lookup state
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1023);
	__type(key, u32);
	__type(value, struct lookup);
} lookups SEC(".maps");

// a hash table for tracking sockets: not used
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);					// thread id
	__type(value, struct sock *);		// socket
} sockets SEC(".maps");

// a hash table for tracking process start times
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);					// process id
	__type(value, u64);					// process start time
} exec_start SEC(".maps");

// the ring buffer for emitting events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


// tracepoint for exec. There is a separate tracepoint for fork.
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
	// read: task->real_parent->tgid using CO:RE
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	if (bpf_get_current_comm(&e->comm, sizeof(e->comm)) < 0) {
		e->comm[0] = '\0';
	}
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	if (bpf_probe_read_str(&e->filename, sizeof(e->filename), (void*)ctx + fname_off) < 0) {
		e->filename[0] = '\0';
	}

	// send it to userspace
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// process exit tracepoint
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
	if (bpf_get_current_comm(&e->comm, sizeof(e->comm)) < 0) {
		e->comm[0] = '\0';
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// DNS Lookup
// entry hook for getaddrinfo
// NOTE: there are more DNS related functions that need to be intercepted
// if we want completeness. Note that DNS perfmormed manually, by sending a UDP request
// or DNS lookup performed by the kernel, will not be captured here.
SEC("uprobe/getaddrinfo")
int BPF_KPROBE(getaddrinfo_enter, const char *hostname, const char *service, 
								  const struct addrinfo *hints, struct addrinfo **res)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	if (!tid) {
		return 0;
	}

	// store the arguments in the map so that we can use them in the ret probe
	struct lookup lookup = {};

	if (bpf_probe_read_user_str(&lookup.question, sizeof(lookup.question), hostname) < 0) {
		// NOTE: can also return since we will not have question. But try anyway since we may be able
		// to get cname.
		lookup.question[0] = '\0';
	}
	lookup.results = res;

	bpf_map_update_elem(&lookups, &tid, &lookup, BPF_ANY);

	return 0;
}

SEC("uretprobe/getaddrinfo")
int BPF_KRETPROBE(getaddrinfo_exit, int ret)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	u32 tid = (u32)id;

	if (!tid) {
		return 0;
	}

	if (ret != 0) {
		goto cleanup;
	}

	struct lookup *lookup = bpf_map_lookup_elem(&lookups, &tid);
	if (!lookup) {
		return 0;
	}

	// results is a linked list. For now we process just the first element.

	struct addrinfo *result = NULL;
	bpf_probe_read_user(&result, sizeof(result), lookup->results);

	struct sockaddr_in *addr = NULL;
	bpf_probe_read_user(&addr, sizeof(addr), &result->ai_addr);

	sa_family_t sin_family = 0;
	bpf_probe_read_user(&sin_family, sizeof(sa_family_t), &addr->sin_family);

	if (sin_family != AF_INET) {
		return 0;
	}

	struct in_addr ipv4_addr;
	if (bpf_probe_read_user(&ipv4_addr, sizeof(ipv4_addr), &addr->sin_addr) < 0) {
		__builtin_memset(&ipv4_addr, 0, sizeof(ipv4_addr));
	}

	fm_dns_lookup_v4_t* e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		goto cleanup;
	}

	e->hdr.op_code = OP_DNS_LOOKUP_V4;
	e->hdr.pid = pid;
	__builtin_memcpy(e->question, lookup->question, sizeof(e->question));
	e->cname[0] = '\0';
	e->ip = ipv4_addr.s_addr;
	// FIXME: the verifier is not happy about using &e->cname as the destination
	// likely need an explicit check to get around it?
	// if (bpf_probe_read_user_str(&e->cname, sizeof(e->cname), result->ai_canonname) < 0) {
	// 	e->cname[0] = '\0';
	// }

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&lookups, &tid);
	return 0;
}


// tracepoint for socket state change.
// this is a deceptively simple but quite powerful hook as it gives us access to the state
// change event, but also to struct sock. We can then use CO:RE to extract data from
// the socket as needed. This is likely sufficient for all the basic socket lifecycle observability
// and is as efficient as it can be, since it is a tracepoint.
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