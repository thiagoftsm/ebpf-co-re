/*
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/perf_event.h>
#include "bpf_helpers.h"
*/

#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "bugs.h"

const volatile size_t monitor_pid = 0;

// /usr/src/linux/samples/bpf/offwaketime_kern.c

struct key_t {
    char target[TASK_COMM_LEN];
    __u32 pid;
    __u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
};

struct value_t {
    __u64 ip;
    __u64 equal;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, struct value_t);
    __uint(max_entries, 32687);
} bug_overflow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 127 * sizeof(u64));
    __uint(max_entries, 10240);
} stackmap SEC(".maps");

/*
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 32687);
} bug_overflow SEC(".maps");
*/

SEC("perf_event")
int bpf_prog1(struct bpf_perf_event_data *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id;
    __u32 tgid = id >> 32;
    
    if (!pid || (pid != monitor_pid && tgid != monitor_pid))
        return 0;

    struct key_t key = { };
    struct value_t data = { };
    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
    struct value_t *value = bpf_map_lookup_elem(&bug_overflow, &key);
    __u64 cip = PT_REGS_IP(&ctx->regs);
    if (value) {
        value->equal = (value->ip == cip);
        value->ip = cip;
    } else {
        data.equal = 1;
        data.ip = cip;
        bpf_map_update_elem(&bug_overflow, &key, &data, BPF_NOEXIST);
    }

    /*
        struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
        struct wokeby_t woke;
        u32 pid;

        pid = _(p->pid);

        bpf_get_current_comm(&woke.name, sizeof(woke.name));
        woke.ret = bpf_get_stackid(ctx, &stackmap, STACKID_FLAGS);

        bpf_map_update_elem(&wokeby, &pid, &woke, BPF_ANY);
    return 0;
    */

/*
    __u64 id = bpf_get_current_pid_tgid();
    __u32 key = id;
    __u32 tgid = id >> 32;
    
    if (key != monitor_pid && tgid != monitor_pid)
        return 0;

    __u64 ip = PT_REGS_IP(&ctx->regs);
    __u64 *value = bpf_map_lookup_elem(&bug_overflow, &ip);
    if (value)
        libnetdata_update_u64(value, 1);
    else {
        id = 1;
        bpf_map_update_elem(&bug_overflow, &ip, &id, BPF_NOEXIST);
    }
*/

    return 0;
}

/*
SEC("kprobe/try_to_wake_up")
int BPF_KPROBE(netdata_wake_up)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id;
    __u32 tgid = id >> 32;
    
    if (pid != monitor_pid && tgid != monitor_pid)
        return 0;

    struct key_t key = { };
    struct value_t data = { };
    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
    struct value_t *value = bpf_map_lookup_elem(&bug_overflow, &key);
    __u64 cip = PT_REGS_IP(ctx);
    if (value) {
        value->equal = (value->ip == cip);
        value->ip = cip;
    } else {
        data.equal = 1;
        data.ip = cip;
        bpf_map_update_elem(&bug_overflow, &key, &data, BPF_NOEXIST);
    }

    return 0;
}
*/

/*
SEC("kprobe/finish_task_switch")
int BPF_KPROBE(netdata_finish_task_switch)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id;
    __u32 tgid = id >> 32;
    
    if (pid != monitor_pid && tgid != monitor_pid)
        return 0;

    struct key_t key = { };
    struct value_t data = { };
    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
    struct value_t *value = bpf_map_lookup_elem(&bug_overflow, &key);
    __u64 cip = PT_REGS_IP(ctx);
    if (value) {
        value->equal = (value->ip == cip);
        value->ip = cip;
    } else {
        data.equal = 1;
        data.ip = cip;
        bpf_map_update_elem(&bug_overflow, &key, &data, BPF_NOEXIST);
    }

    return 0;
}
*/

char _license[] SEC("license") = "GPL";

