extern "C" {
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "flowmon.h"
#include "flowmon.skel.h"
}

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

static int load_program() {
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
        fprintf(stderr, "Failed to load and verify BPF skeleton");
        goto err;
    }

    // attach (start) the program
    if (flowmon_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BFP skeleton");
        goto err;
    }

    printf("Successfully attached BFP skeleton\n");
    return 0;

err:
    flowmon_bpf__destroy(skel);
    skel = NULL;
    return 1;
}

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

const char * get_tcp_state_name(int number) {
    if (number < 0 || number >= (int)(sizeof(tcp_states)/sizeof(char*))) {
        return "";
    }
    return tcp_states[number];
}

// main event handler for events in the ring buffer
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
                printf("%-8s %-5s %-16s %-7d %-7u %-16s %-16s\n", 
                    ts, "SOCKV4", "", e->hdr.pid,
                    e->net_ns, 
                    get_tcp_state_name(e->old_state),
                    get_tcp_state_name(e->new_state));
            }
            break;
        default:
            printf("%-8s %-5s\n", ts, "UNKNOWN");
            break;
    }

	return 0;
}

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

static void finish_processing_loop()
{
    ring_buffer__free(rb);
}

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

    // increase RLIMIT_MEMLOCK to allow BPF systems to do whatever it needs
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

	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");

    // process the data
    err = run_processing_loop();

cleanup:
    finish_processing_loop();
    unload_program();

    return err < 0 ? -err : 0;  
}