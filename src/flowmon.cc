extern "C" {
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/limits.h>
#include "flowmon.h"
#include "flowmon.skel.h"
#include "uprobe_helpers.h"
}
#include <algorithm>

#define FORMAT_IP(ip) ((ip) & 0xff), ((ip)>>8 & 0xff), ((ip)>>16 & 0xff), ((ip)>>24 & 0xff)


static struct flowmon_bpf *skel = NULL;
struct ring_buffer *rb = NULL;
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit() {
    struct rlimit rlimit_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlimit_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: error=%d\n", errno);
        exit(1);
    }
}

// obtains the path to libc loaded in our process
static int get_libc_path(char *path, size_t size)
{
	FILE *f;
	char buf[PATH_MAX] = {};
	char *filename;
	float version;

	f = fopen("/proc/self/maps", "r");
	if (!f){
		return -errno;
    }

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf) {
			continue;
        }

		filename = strrchr(buf, '/') + 1;
		if (sscanf(filename, "libc-%f.so", &version) == 1) {
            size_t len = strlen(buf);
			memcpy(path, buf, std::min(len, size-1));
            path[len] = '\0';

			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

// To attach a uprobe, we need to specify the library and the offset within the
// library of the function we want to attach to. Similarly to kprobes, there are
// two types of probes: uprobe - at entry, uretprobe - at exit.
// Uprobes seem to work similarly to kprobes:
//   - each kprobe, internally has a pre_handler, post_handler, and a fault_handler
//   - the probed instruction is copied
//   - the first byte of the instruction is replaced with int3
//   - when a CPU reaches the probed instruction, a trap occurs and the registeres are saved
//   - kprobe pre_handler is invoked
//   - system single steps the copy of the probed instruction
//      - done in the copy since in place will require removal of breakpoint instruction and that
//        can cause other threads to not hit the probe.
//   - after the instruction is single stepped, the post_handler is invoked
//   - execution follows with instruction after probe point.
// Kretprobes work as follows:
//    - a probe is added to the entry of the function
//    - this probe saves the return address and replaces it with the address

// attaches uprobes included in the ebpf program
static int attach_uprobes(flowmon_bpf* skel)
{
    int err;
	char libc_path[PATH_MAX] = {};
    off_t func_off;

    // NOTE: there may be multiple libc-s in use on the system.
    // Here we use the version loaded by our process.
	err = get_libc_path(libc_path, sizeof(libc_path));
	if (err) {
		fprintf(stderr, "Could not find libc.so\n");
		return -1;
	}

    printf("Libc path=%s\n", libc_path);

    // locate getaddrinfo
	func_off = get_elf_func_offset(libc_path, "getaddrinfo");
	if (func_off < 0) {
		fprintf(stderr, "Could not find getaddrinfo in %s\n", libc_path);
		return -1;
	}

    printf("getaddrinfo offset=%lx\n", func_off);

    // apparently we do not need to detach probes explicitly - they will be
    // handled by the call to destroy.

    // the kprobe - needed to set context and preserve arguments
	skel->links.getaddrinfo_enter = bpf_program__attach_uprobe(
            skel->progs.getaddrinfo_enter,
            false,  // uprobe
			-1,     // every pid
            libc_path,
            func_off);
    
    // check if an error occurred
    err = libbpf_get_error(skel->links.getaddrinfo_enter);
	if (err) {
		fprintf(stderr, "Failed to attach getaddrinfo: %d\n", err);
		return -1;
	}

    // the kretprobe - does the actual work
	skel->links.getaddrinfo_exit = bpf_program__attach_uprobe(
            skel->progs.getaddrinfo_exit,
            true,  // uretprobe
			-1,     // every pid
            libc_path,
            func_off);
    
    err = libbpf_get_error(skel->links.getaddrinfo_exit);
	if (err) {
		fprintf(stderr, "Failed to attach getaddrinfo: %d\n", err);
		return -1;
	}

    return 0;
}

// Loads and activates the eBPF program
static int load_program()
{
    if (skel != NULL) {
        fprintf(stderr, "Program is already loaded\n");
        return 1;
    }

    // create the skeleton
    skel = flowmon_bpf__open();
    if (!skel) {
        fprintf(stderr, "Could not open BFP skeleton\n");
        return 1;
    }

    // load and verify the program
    if (flowmon_bpf__load(skel)) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto err;
    }

    // attach (start) the program
    if (flowmon_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BFP skeleton\n");
        goto err;
    }

    if (attach_uprobes(skel)) {
        fprintf(stderr, "Failed to attach uprobes\n");
        goto err;
    }

    printf("Successfully attached BFP skeleton\n");
    return 0;

err:
    flowmon_bpf__destroy(skel);
    skel = NULL;
    return 1;
}

// Unloads the eBPF program
static void unload_program()
{
    flowmon_bpf__destroy(skel);
    skel = NULL;
}

static const char* tcp_states[] = {
    "",                 // 0
    "ESTABLISHED",      // 1
    "SYN_SENT",         // 2
    "SYN_RECV",         // 3
    "FIN_WAIT1",        // 4
    "FIN_WAIT2",        // 5
    "TIME_WAIT",        // 6
    "CLOSE",            // 7
    "CLOSE_WAIT",       // 8
    "LAST_ACK",         // 9
    "LISTEN",           // 10
    "CLOSING",          // 11
    "NEW_SYN_RECV"      // 12
};

static const char * get_tcp_state_name(int number) {
    if (number < 0 || number >= (int)(sizeof(tcp_states)/sizeof(char*))) {
        return "";
    }
    return tcp_states[number];
}

// main event handler for events in the ring buffer
// gets called whenever poll indicates that there is data in the buffer
// the runtime calls us only for events that are valid: incomplete, abandoned events are
// skipped.
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const fm_header_t *header = (fm_header_t*)data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    switch(header->op_code) {
        case OP_PROCESS_EXEC:
            {
                const fm_exec_t * e = (fm_exec_t*)data;
                printf("%-8s %-5s %-16s %-7d %-7d %s\n",
                    ts, "EXEC", e->comm, e->hdr.pid, e->ppid, e->filename);
            }
            break;
        case OP_PROCESS_EXIT:
            {
                const fm_exit_t * e = (fm_exit_t*)data;
                printf("%-8s %-5s %-16s %-7d %-7d [%u]",
                    ts, "EXIT", e->comm, e->hdr.pid, e->ppid, e->exit_code);
                if (e->duration_ns) {
                    printf(" (%llums)", e->duration_ns / 1000000);
                }
                printf("\n");
            }
            break;
        case OP_SOCK_STATE_CHANGE_V4:
            {
                const fm_sock_state_change_v4_t *e = (fm_sock_state_change_v4_t*)data;
                printf("%-8s %-5s %-16s %-7d %-7u %-16s %-16s %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", 
                    ts, "SOCK4", "", e->hdr.pid,
                    e->net_ns, 
                    get_tcp_state_name(e->old_state),
                    get_tcp_state_name(e->new_state),
                    FORMAT_IP(e->saddr), e->sport,
                    FORMAT_IP(e->daddr), e->dport);
            }
            break;
        case OP_DNS_LOOKUP_V4:
            {
                const fm_dns_lookup_v4_t *e = (fm_dns_lookup_v4_t*)data;
                printf("%-8s %-5s %-16s %-7d %s [%s] %d.%d.%d.%d\n",
                    ts, "DNS4", "", e->hdr.pid,
                    e->question,
                    e->cname,
                    FORMAT_IP(e->ip));
            }
            break;
        default:
            printf("%-8s %-5s\n", ts, "UNKNOWN");
            break;
    }

	return 0;
}

// this works for perf buffers, but I could not find equivalent for ring buffers
// static void handle_lost_events(void *ctx, int cpu, void *data, __u32 data_sz)
// {
//     fprintf(stdout, "Lost %llu events on CPU #%d\n", lost_cnt, cpu);
// }

// initializes the process of the ring buffer
static int init_processing_loop()
{
    // start the event processing loop
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
	}

    return 0;
}

// ends the processing of the ring buffer
static void finish_processing_loop()
{
    ring_buffer__free(rb);
}

// executes the event loop
static int run_processing_loop()
{
    int err;

    while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		// ctrl + c
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	}

    return err;
}

int main(int argc, char **argv) {
    int err = 0;

    // increase RLIMIT_MEMLOCK to allow the BPF system to do whatever it needs
    bump_memlock_rlimit();
    
    // set libbpf callback
    libbpf_set_print(libbpf_print_fn); 

	// terminate gracefully
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    // attempt to load the program
    if (load_program()) {
        return 1;
    }

    // init the processing loop
    if (init_processing_loop()) {
        err = -1;
        goto cleanup;
    }

    // print column header
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");

    // process the data
    err = run_processing_loop();

cleanup:
    finish_processing_loop();
    unload_program();

    return err < 0 ? -err : 0;  
}