#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "bugs.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

// Memory Leak
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10240);
} bug_sizes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} bug_ctrl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, ebpf_mem_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} bug_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, ebpf_allocated_mem_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} bug_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10240);
} bugs_memptrs SEC(".maps");

// Overflow
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10240);
} bugs_overflow SEC(".maps");

/************************************************************************************
 *
 *                           COMMON FUNCTIONS
 *
 ***********************************************************************************/

static int ebpf_free_enter(const void *address)
{
    __u64 addr = (__u64)address;

    ebpf_allocated_mem_t *addr_data = bpf_map_lookup_elem(&bug_addr, &addr);
    if (!addr_data)
        return 0;


    __u32 key = 0;
    __u32 tgid = 0;
    ebpf_mem_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &bug_ctrl, &bug_stats);
    if (!fill)
        return 0;

    libnetdata_update_u32(&fill->released, 1);
    libnetdata_update_u64(&fill->size_released, addr_data->size);

    bpf_map_delete_elem(&bug_addr, &addr);

    return 0;
}

static int ebpf_update_exit_status(void *ctx, __u64 address)
{
    ebpf_mem_stat_t *fill;
    ebpf_mem_stat_t data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &bug_ctrl, &bug_stats);
    if (!fill)
        return 0;

    if (!address) {
        libnetdata_update_u32(&fill->oom, 1);
        return 0;
    }

    u64 *stored = bpf_map_lookup_elem(&bug_sizes, &key);
    if (!stored)
        return 0;

    ebpf_allocated_mem_t addr_data = {};
    addr_data.size = *stored;
    libnetdata_update_uid_gid(&data.uid, &data.gid);
    bpf_get_current_comm(&data.name, TASK_COMM_LEN);

    bpf_map_update_elem(&bug_addr, &address, &addr_data, BPF_ANY);

    bpf_map_delete_elem(&bug_sizes, &key);

    return 0;
}

static __always_inline int ebpf_alloc_exit_entry(struct pt_regs *ctx)
{
    return ebpf_update_exit_status(ctx, PT_REGS_RC(ctx));
}

static __always_inline int ebpf_alloc_enter(size_t size)
{
    ebpf_mem_stat_t *fill;
    ebpf_mem_stat_t data = {};
    __u32 key = 0;
    __u32 tgid = 0;
    fill = netdata_get_pid_structure(&key, &tgid, &bug_ctrl, &bug_stats);

    if (fill) {
        libnetdata_update_u64(&fill->size_allocated, size);
        libnetdata_update_u32(&fill->alloc, 1);
    } else {
        data.tgid = tgid;
        data.alloc = 1;
        data.size_allocated = size;
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);

        bpf_map_update_elem(&bug_stats, &key, &data, BPF_ANY);
    }

    __u64 store_size = size;
    bpf_map_update_elem(&bug_sizes, &key, &store_size, BPF_ANY);

    return 0;
}

static __always_inline void ebpf_overflow_entry(int safe)
{
    ebpf_mem_stat_t *fill;
    ebpf_mem_stat_t data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &bug_ctrl, &bug_stats);

    if (fill) {
        libnetdata_update_u64(&fill->str_copy_entry, 1);
        if (safe)
            libnetdata_update_u32(&fill->safe_function, 1);
        else
            libnetdata_update_u32(&fill->unsafe_function, 1);
    } else {
        data.tgid = tgid;
        data.str_copy_entry = 1;
        if (safe)
            data.safe_function = 1;
        else
            data.unsafe_function = 1;

        libnetdata_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);

        bpf_map_update_elem(&bug_stats, &key, &data, BPF_ANY);
    }
}

static __always_inline int ebpf_probe_signal(int sig)
{
    ebpf_mem_stat_t *fill;
    ebpf_mem_stat_t data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    fill = netdata_get_pid_structure(&key, &tgid, &bug_ctrl, &bug_stats);

    if (fill) {
        libnetdata_update_s64(&fill->signal, -fill->signal);
        libnetdata_update_s64(&fill->signal, sig);
    } else {
        data.tgid = tgid;
        data.signal = 1;
        libnetdata_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);

        bpf_map_update_elem(&bug_stats, &key, &data, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *
 *                           MEMLEAK FUNCTION
 *
 ***********************************************************************************/

// U(RET)PROBE are like K(RET)PROBE 

SEC("uprobe/malloc")
int BPF_UPROBE(malloc_enter, size_t size)
{
    return ebpf_alloc_enter(size);
}

SEC("uretprobe/malloc")
int BPF_URETPROBE(malloc_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}

SEC("uprobe/free")
int BPF_UPROBE(free_enter, void *address)
{
    return ebpf_free_enter(address);
}

SEC("uprobe/calloc")
int BPF_UPROBE(calloc_enter, size_t nmemb, size_t size)
{
    return ebpf_alloc_enter(nmemb * size);
}

SEC("uretprobe/calloc")
int BPF_URETPROBE(calloc_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}

SEC("uprobe/realloc")
int BPF_UPROBE(realloc_enter, void *ptr, size_t size)
{
    (void)ebpf_free_enter(ptr);

    return ebpf_alloc_enter(size);
}

SEC("uretprobe/realloc")
int BPF_URETPROBE(realloc_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}

SEC("uprobe/mmap")
int BPF_UPROBE(mmap_enter, void *address, size_t size)
{
    return ebpf_alloc_enter(size);
}

SEC("uretprobe/mmap")
int BPF_URETPROBE(mmap_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}

SEC("uprobe/munmap")
int BPF_UPROBE(munmap_enter, void *address)
{
    return ebpf_free_enter(address);
}

SEC("uprobe/posix_memalign")
int BPF_UPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
    __u64 memptr64 = (u64)(size_t)memptr;
    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bugs_memptrs, &tid, &memptr64, BPF_ANY);

    return ebpf_alloc_enter(size);
}

SEC("uretprobe/posix_memalign")
int BPF_URETPROBE(posix_memalign_exit)
{
    __u64 *memptr64;
    __u32 tid = bpf_get_current_pid_tgid();

    memptr64 = bpf_map_lookup_elem(&bugs_memptrs, &tid);
    if (!memptr64)
        return 0;

    bpf_map_delete_elem(&bugs_memptrs, &tid);

    void *addr;
    if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
        return 0;

    const __u64 addr64 = (__u64)(size_t)addr;
    return ebpf_update_exit_status(ctx, addr64);
}

SEC("uprobe/memalign")
int BPF_UPROBE(memalign_enter, size_t alignment, size_t size)
{
    return ebpf_alloc_enter(size);
}

SEC("uretprobe/memalign")
int BPF_URETPROBE(memalign_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}

/*
SEC("uprobe/aligned_alloc")
int BPF_UPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
    return ebpf_alloc_enter(size);
}

SEC("uretprobe/aligned_alloc")
int BPF_URETPROBE(aligned_alloc_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}

SEC("uprobe/valloc")
int BPF_UPROBE(valloc_enter, size_t size)
{
    return ebpf_alloc_enter(size);
}

SEC("uretprobe/valloc")
int BPF_URETPROBE(valloc_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}
*/


/*
SEC("uprobe/pvalloc")
int BPF_UPROBE(pvalloc_enter, size_t size)
{
    return ebpf_alloc_enter(size);
}

SEC("uretprobe/pvalloc")
int BPF_URETPROBE(pvalloc_exit)
{
    return ebpf_alloc_exit_entry(ctx);
}
*/

/************************************************************************************
 *
 *                           OVERFLOW FUNCTION
 *
 ***********************************************************************************/

// https://linuxppc-dev.ozlabs.narkive.com/RG52tkkd/patchv2-net-1-3-samples-bpf-fix-build-breakage-with-map-perf-test-user-c
// Instruction pointer

    /*
    __u64 val = PT_REGS_IP(ctx);
    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bugs_overflow, &tid, &val, BPF_ANY);
    */

// U(RET)PROBE are like K(RET)PROBE 
SEC("uprobe/snprintf")
int BPF_UPROBE(snprintf_enter)
{
    ebpf_overflow_entry(1);

    return 0;
}

SEC("uprobe/sprintf")
int BPF_UPROBE(sprintf_enter)
{
    ebpf_overflow_entry(0);

    return 0;
}

SEC("uprobe/vfprintf")
int BPF_UPROBE(vfprintf_enter)
{
    ebpf_overflow_entry(0);

    return 0;
}


SEC("uprobe/memcpy")
int BPF_UPROBE(memcpy_enter)
{
    ebpf_overflow_entry(1);

    return 0;
}

SEC("uprobe/gets")
int BPF_UPROBE(gets_enter)
{
    ebpf_overflow_entry(0);

    return 0;
}

SEC("uprobe/fgetc")
int BPF_UPROBE(fgetc_enter)
{
    ebpf_overflow_entry(0);

    return 0;
}

/************************************************************************************
 *
 *                           SIGNAL FUNCTION
 *
 ***********************************************************************************/

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
    //pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    return ebpf_probe_signal(sig);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tkill_entry(struct trace_event_raw_sys_enter *ctx)
{
   // pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    return ebpf_probe_signal(sig);
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tgkill_entry(struct trace_event_raw_sys_enter *ctx)
{
   // pid_t tpid = (pid_t)ctx->args[1];
    int sig = (int)ctx->args[2];

    return ebpf_probe_signal(sig);
}


// ----------------- REMOVE ME after demo

SEC("fentry/release_task")
int BPF_PROG(netdata_release_task_fentry)
{
    __u32 key = 0;
    __u32 tgid = 0;
    ebpf_mem_stat_t *fill = netdata_get_pid_structure(&key, &tgid, &bug_ctrl, &bug_stats);
    if (!fill)
        return 0;

    libnetdata_update_u32(&fill->stopped, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";

