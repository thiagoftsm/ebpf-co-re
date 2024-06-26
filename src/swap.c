#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_defs.h"
#include "netdata_tests.h"
#include "netdata_core_common.h"
#include "netdata_swap.h"

#include "swap.skel.h"

// Alma Linux modified internal name, this structure was brought for it.
static ebpf_specify_name_t swap_names[] = { {.program_name = "netdata_swap_read_folio_probe",
                                                  .function_to_attach = "swap_read_folio",
                                                  .length = 15,
                                                  .optional = NULL,
                                                  .retprobe = 0},
                                                 {.program_name = "netdata_swap_readpage_probe",
                                                  .function_to_attach = "swap_readpage",
                                                  .length = 13,
                                                  .optional = NULL,
                                                  .retprobe = 0},
                                                 {.program_name = NULL}};


char *function_list[] = { NULL, // Filled after to discover available functions
                          "swap_writepage"
};
// This preprocessor is defined here, because it is not useful in kernel-colector
#define NETDATA_SWAP_RELEASE_TASK 2

static void netdata_ebpf_disable_probe(struct swap_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_swap_readpage_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_swap_read_folio_probe, false);
    bpf_program__set_autoload(obj->progs.netdata_swap_writepage_probe, false);
}

static inline void netdata_ebpf_disable_specific_probe(struct swap_bpf *obj)
{
    if (swap_names[0].optional) {
        bpf_program__set_autoload(obj->progs.netdata_swap_readpage_probe, false);
    } else  {
        bpf_program__set_autoload(obj->progs.netdata_swap_read_folio_probe, false);
    }
}

static void netdata_ebpf_disable_trampoline(struct swap_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_swap_readpage_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_swap_read_folio_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_swap_writepage_fentry, false);
}

static inline void netdata_ebpf_disable_specific_trampoline(struct swap_bpf *obj)
{
    if (swap_names[0].optional) {
        bpf_program__set_autoload(obj->progs.netdata_swap_readpage_fentry, false);
    } else  {
        bpf_program__set_autoload(obj->progs.netdata_swap_read_folio_fentry, false);
    }
}

static void netdata_set_trampoline_target(struct swap_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_swap_readpage_fentry, 0,
                                   function_list[NETDATA_KEY_SWAP_READPAGE_CALL]);

    bpf_program__set_attach_target(obj->progs.netdata_swap_writepage_fentry, 0,
                                   function_list[NETDATA_KEY_SWAP_WRITEPAGE_CALL]);
}

static int attach_kprobe(struct swap_bpf *obj)
{
    int ret;
    if (swap_names[0].optional) {
        obj->links.netdata_swap_read_folio_probe = bpf_program__attach_kprobe(obj->progs.netdata_swap_read_folio_probe,
                                                                        false, function_list[NETDATA_KEY_SWAP_READPAGE_CALL]);
        ret = libbpf_get_error(obj->links.netdata_swap_read_folio_probe);
    } else {
        obj->links.netdata_swap_readpage_probe = bpf_program__attach_kprobe(obj->progs.netdata_swap_readpage_probe,
                                                                        false, function_list[NETDATA_KEY_SWAP_READPAGE_CALL]);
        ret = libbpf_get_error(obj->links.netdata_swap_readpage_probe);
    }

    if (ret)
        return -1;

    obj->links.netdata_swap_writepage_probe = bpf_program__attach_kprobe(obj->progs.netdata_swap_writepage_probe,
                                                                         false, function_list[NETDATA_KEY_SWAP_WRITEPAGE_CALL]);
    ret = libbpf_get_error(obj->links.netdata_swap_writepage_probe);
    if (ret)
        return -1;

    return 0;
}

static int ebpf_load_and_attach(struct swap_bpf *obj, int selector)
{
    if (!selector) { //trampoline
        netdata_ebpf_disable_probe(obj);
        netdata_ebpf_disable_specific_trampoline(obj);

        netdata_set_trampoline_target(obj);
    } else if (selector) { // probe
        netdata_ebpf_disable_trampoline(obj);
        netdata_ebpf_disable_specific_probe(obj);
    }

    int ret = swap_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector) // attach kprobe
        ret = attach_kprobe(obj);
    else {
        ret = swap_bpf__attach(obj);
    }

    if (!ret) {
        fprintf(stdout, "%s loaded with success\n", (!selector) ? "trampoline" : "probe");
    }

    return ret;
}

static void ebpf_fill_tables(int global, int apps)
{
    (void)ebpf_fill_global(global);

    netdata_swap_access_t swap_data = { .read = 1, .write = 1 };

    uint32_t idx;
    for (idx = 0; idx < NETDATA_EBPF_CORE_MIN_STORE; idx++) {
        int ret = bpf_map_update_elem(apps, &idx, &swap_data, 0);
        if (ret)
            fprintf(stderr, "Cannot insert value to apps table.");
    }
}

static int swap_read_apps_array(int fd, int ebpf_nprocs)
{
    netdata_swap_access_t stored[ebpf_nprocs];

    int key, next_key;
    key = next_key = 0;
    uint64_t counter = 0;
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
            counter++;
        }
        memset(stored, 0, ebpf_nprocs * sizeof(netdata_swap_access_t));

        key = next_key;
    }

    if (counter) {
        fprintf(stdout, "Apps data stored with success. It collected %lu pids\n", counter);
        return 0;
    }

    return 2;
}

int ebpf_load_swap(int selector, enum netdata_apps_level map_level)
{
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = NETDATA_CORE_PROCESS_NUMBER;

    struct swap_bpf *obj = NULL;

    obj = swap_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != NETDATA_MODE_PROBE) {
        swap_bpf__destroy(obj);

        obj = swap_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = NETDATA_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }


    if (!ret) {
        int fd = bpf_map__fd(obj->maps.swap_ctrl);
        ebpf_core_fill_ctrl(obj->maps.swap_ctrl, map_level);

        fd = bpf_map__fd(obj->maps.tbl_swap);
        int fd2 = bpf_map__fd(obj->maps.tbl_pid_swap);
        ebpf_fill_tables(fd, fd2);
        sleep(60);
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_SWAP_END);
        if (!ret) {
            ret =  swap_read_apps_array(fd2, ebpf_nprocs);
            if (ret)
                fprintf(stdout, "Empty apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);
    }

    swap_bpf__destroy(obj);

    return ret;
load_error:
    fprintf(stderr, "Cannot open or load BPF object\n");
    return 2;
}

static inline void fill_swap_fcnt()
{
    ebpf_update_names(swap_names);
    int i;
    for (i = 0; swap_names[i].program_name ; i++) {
        if (swap_names[i].optional) {
            function_list[NETDATA_KEY_SWAP_READPAGE_CALL] = swap_names[i].optional;
            break;
        }
    }
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  0 },
        {"probe",       no_argument,    0,  0 },
        {"tracepoint",  no_argument,    0,  0 },
        {"trampoline",  no_argument,    0,  0 },
        {"pid",         required_argument,    0,  0 },
        {0, 0, 0, 0}
    };

    int selector = NETDATA_MODE_TRAMPOLINE;
    int option_index = 0;
    enum netdata_apps_level map_level = NETDATA_APPS_LEVEL_REAL_PARENT;
    while (1) {
        int c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {
            case NETDATA_EBPF_CORE_IDX_HELP: {
                          ebpf_core_print_help(argv[0], "swap", 1, 1);
                          exit(0);
                      }
            case NETDATA_EBPF_CORE_IDX_PROBE: {
                          selector = NETDATA_MODE_PROBE;
                          break;
                      }
            case NETDATA_EBPF_CORE_IDX_TRACEPOINT: {
                          selector = NETDATA_MODE_PROBE;
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
                          break;
                      }
            case NETDATA_EBPF_CORE_IDX_TRAMPOLINE: {
                          selector = NETDATA_MODE_TRAMPOLINE;
                          break;
                      }
            case NETDATA_EBPF_CORE_IDX_PID: {
                          int user_input = (int)strtol(optarg, NULL, 10);
                          map_level = ebpf_check_map_level(user_input);
                          break;
                      }
            default: {
                         break;
                     }
        }
    }

    // Adjust memory
    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    libbpf_set_print(netdata_libbpf_vfprintf);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    fill_swap_fcnt();
    if (!function_list[NETDATA_KEY_SWAP_READPAGE_CALL]) {
        fprintf(stderr, "Cannot find all necessary functions\n");
        return 0;
    }

    struct btf *bf = NULL;
    if (!selector) {
        bf = netdata_parse_btf_file((const char *)NETDATA_BTF_FILE);
        if (bf) {
            selector = ebpf_find_functions(bf, selector, function_list, NETDATA_SWAP_END);
            btf__free(bf);
        }
    }

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_load_swap(selector, map_level) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }

    return 0;
}

