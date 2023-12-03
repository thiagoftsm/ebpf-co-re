#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "netdata_defs.h"
#include "netdata_tests.h"
#include "netdata_core_common.h"

#include "bugs_memleak.skel.h"

static const char *default_object = { "/lib64/libc-2.38.so" };

struct variables {
    int self_test;
    int pid;
    const char *object;
} vars =  {
    .self_test = 1,
    .pid = 1,
    .object = NULL,
};


#define __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe)   \
        do {                                                                       \
          LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name,        \
                                  .retprobe = is_retprobe);                                    \
          skel->links.prog_name = bpf_program__attach_uprobe_opts(                 \
                  skel->progs.prog_name, vars.pid, binary_path, 0, &uprobe_opts);       \
        } while (false)

#define __CHECK_PROGRAM(skel, prog_name)               \
        do {                                               \
          if (!skel->links.prog_name) {                    \
                perror("no program attached for " #prog_name); \
                return -errno;                                 \
          }                                                \
        } while (false)

#define __ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name,     \
                                                                is_retprobe)                                \
        do {                                                                    \
          __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe); \
          __CHECK_PROGRAM(skel, prog_name);                                     \
        } while (false)

#define ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name)     \
        __ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, binary_path, sym_name, prog_name)  \
        __ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, true)


/*
 * Find the path of a library using ldconfig.
 */
char *ebpf_find_library_path(const char *libname) {
    char cmd[128];
    static char path[512];
    FILE *fp;

    // Construct the ldconfig command with grep
    snprintf(cmd, sizeof(cmd), "ldconfig -p | grep %s", libname);

    // Execute the command and read the output
    fp = popen(cmd, "r");
    if (fp == NULL) {
            perror("Failed to run ldconfig");
            return NULL;
    }

    // Read the first line of output which should have the library path
    if (fgets(path, sizeof(path) - 1, fp) != NULL) {
        // Extract the path from the ldconfig output
        char *start = strrchr(path, '>');
        if (start && *(start + 1) == ' ') {
            memmove(path, start + 2, strlen(start + 2) + 1);
            char *end = strchr(path, '\n');
            if (end) {
                *end = '\0';  // Null-terminate the path
            }
            pclose(fp);
            return path;
        }
    }

    pclose(fp);
    return NULL;
}


int ebpf_attach_leak_uprobes(struct bugs_memleak_bpf *skel)
{
    ATTACH_UPROBE_CHECKED(skel, vars.object, malloc, malloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, vars.object, malloc, malloc_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, calloc, calloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, vars.object, calloc, calloc_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, realloc, realloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, vars.object, realloc, realloc_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, mmap, mmap_enter);
    ATTACH_URETPROBE_CHECKED(skel, vars.object, mmap, mmap_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, posix_memalign, posix_memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, vars.object, posix_memalign, posix_memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, memalign, memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, vars.object, memalign, memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, free, free_enter);
    ATTACH_UPROBE_CHECKED(skel, vars.object, munmap, munmap_enter);

    ATTACH_UPROBE_CHECKED(skel, vars.object, snprintf, snprintf_enter);
//    ATTACH_UPROBE_CHECKED(skel, vars.object, snprintf, snprintf_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, sprintf, sprintf_enter);
//    ATTACH_UPROBE_CHECKED(skel, vars.object, sprintf, sprintf_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, vfprintf, vfprintf_enter);
//    ATTACH_UPROBE_CHECKED(skel, vars.object, vfprintf, vfprintf_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, memcpy, memcpy_enter);
//    ATTACH_UPROBE_CHECKED(skel, vars.object, memcpy, memcpy_exit);

    ATTACH_UPROBE_CHECKED(skel, vars.object, gets, gets_enter);

    ATTACH_UPROBE_CHECKED(skel, vars.object, fgetc, fgetc_enter);

    /*
    ATTACH_UPROBE_CHECKED(skel, vars.object, strcpy, strcpy_enter);
    ATTACH_UPROBE_CHECKED(skel, vars.object, strcpy, strcpy_exit);
    */

    /*
    // the following probes are intentinally allowed to fail attachment

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, vars.object, valloc, valloc_enter);
    ATTACH_URETPROBE(skel, vars.object, valloc, valloc_exit);

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, vars.object, pvalloc, pvalloc_enter);
    ATTACH_URETPROBE(skel, vars.object, pvalloc, pvalloc_exit);

    // added in C11
    ATTACH_UPROBE(skel, vars.object, aligned_alloc, aligned_alloc_enter);
    ATTACH_URETPROBE(skel, vars.object, aligned_alloc, aligned_alloc_exit);
    */

    return 0;
}

static int ebpf_bugs_tests()
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);

    libbpf_set_print(netdata_libbpf_vfprintf);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct bugs_memleak_bpf *skel = bugs_memleak_bpf__open_opts(&open_opts);
    if (!skel) {
        return -1;
    }

    skel->rodata->monitor_pid = vars.pid;

    if (bugs_memleak_bpf__load(skel)) {
        fprintf(stderr, "Fail to load bpf program.\n");
        return -1;
    }

    bpf_program__set_attach_target(skel->progs.netdata_release_task_fentry, 0,
                                   "release_task");

    if (ebpf_attach_leak_uprobes(skel))
        return -1;

    if (bugs_memleak_bpf__attach(skel)) {
        fprintf(stderr, "Fail to attach bpf program.\n");
        return -1;
    }

    int i;
    for (i = 0; i < 5; i++ ) {
        sleep(1);
    }

    bugs_memleak_bpf__destroy(skel);
    return 0;
}

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

    if (!vars.object) {
        char *val = ebpf_find_library_path("libc-2.38.so");
        vars.object = (val) ? val : default_object;
    }

    fprintf(stdout, "Running with library %s\n", vars.object);

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
