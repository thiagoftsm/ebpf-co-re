#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "netdata_defs.h"
#include "netdata_tests.h"
#include "netdata_core_common.h"

#include "bugs_overflow.skel.h"

struct variables {
    int self_test;
    int pid;
    const char *object;
} vars =  {
    .self_test = 1,
    .pid = 1,
    .object = NULL,
};

static int nr_cpus;
static int map_fd;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                                struct bpf_link *links[])
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .freq = 1,
        .watermark = 1,
        .sample_period = freq,
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };
    int i, fd;

    for (i = 0; i < nr_cpus; i++) {
        fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
        if (fd < 0) {
            // Ignore CPU that is offline 
                        if (errno == ENODEV)
                                continue;
                        fprintf(stderr, "failed to init perf sampling: %s\n",
                                strerror(errno));
                        return -1;
                }
                links[i] = bpf_program__attach_perf_event(prog, fd);
                if (!links[i]) {
                        fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
                        close(fd);
                        return -1;
                }
    }

        return 0;
}

static int ebpf_bugs_tests()
{
    nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    struct bpf_link **links = calloc(nr_cpus, sizeof(struct bpf_link *));
    if (!links)
        return 1;

    struct bugs_overflow_bpf *obj = bugs_overflow_bpf__open();

    obj->rodata->monitor_pid = vars.pid;
    
    if (bugs_overflow_bpf__load(obj)) {
        fprintf(stderr, "Fail to load bpf program.\n");
        return 2;
    }

    if (open_and_attach_perf_event(5, obj->progs.bpf_prog1, links)) {
        goto endfct;
    }

endfct:
    int i;
    for (i = 0; i < nr_cpus; i++)
        bpf_link__destroy(links[i]);

    bugs_overflow_bpf__destroy(obj);

    return 0;
}

    /*
static int ebpf_bugs_tests()
{
    struct bugs_overflow_bpf *obj = bugs_overflow_bpf__open();

    int ret;
    if (bugs_overflow_bpf__load(obj)) {
        ret = 1;
        goto endfct;
    }

    obj->links.netdata_wake_up = bpf_program__attach_kprobe(obj->progs.netdata_wake_up,
                                                           false, "try_to_wake_up");
    ret = libbpf_get_error(obj->links.netdata_wake_up);
    if (ret)
        goto endfct;

    obj->links.netdata_finish_task_switch = bpf_program__attach_kprobe(obj->progs.netdata_finish_task_switch,
                                                           false, "finish_task_switch");
    ret = libbpf_get_error(obj->links.netdata_finish_task_switch);
    if (ret)
        goto endfct;

    ret ^= ret;
endfct:
    bugs_overflow_bpf__destroy(obj);
    return 0;
}
        */

static inline void ebpf_bugs_print_help(char *name, char *info) {
    fprintf(stdout, "%s tests if it is possible to monitor %s on host\n\n"
                    "The following options are available:\n\n"
                    "--help       : Prints this help.\n"
                    "--pid        : PID value to monitor.\n"
                    "--library    : Libc name on your environment.\n"
                    , name, info);
}


int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument, 0,  0 },
        {"pid",         required_argument,  0,  0 },
        {"library",     required_argument,  0,  0 },
        {0,             no_argument, 0, 0}
    };

    int option_index = 0;
    while (1) {
        int c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {
            case NETDATA_EBPF_CORE_IDX_HELP: {
                          ebpf_bugs_print_help(argv[0], "bugs");
                          exit(0);
                    }
            case 1: {
                          vars.pid = (int)strtol(optarg, NULL, 10);
                          break;
                    }
            case 2: {
                          vars.object = optarg;
                          break;
                     }
            default: {
                         break;
                     }
        }
    }

    if (vars.pid < 0) {
        vars.pid = getpid();
        vars.self_test = 1;
        fprintf(stderr, "I am going to monitor myself ( pid %d)\n", vars.pid);
    } else {
        fprintf(stdout, "Monitoring pid %d\n", vars.pid);
    }

    // Adjust memory
    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    if (ebpf_bugs_tests())
        return 2;

    return 0;
}
