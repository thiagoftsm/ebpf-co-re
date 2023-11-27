#ifndef _NETDATA_BUGS_H_
# define _NETDATA_BUGS_H_ 1

typedef struct ebpf_mem_stat {
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u64 size_allocated;
    __u64 size_released;
    __u64 str_copy_entry;

    __u32 oom;
    __s64 signal;

    __u32 alloc;
    __u32 released;

    __u32 stopped;
} ebpf_mem_stat_t;

typedef struct ebpf_allocated_mem {
    __u64 addr;
    __u64 size;
} ebpf_allocated_mem_t;

typedef struct ebpf_overflow_stat {
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];
} ebpf_overflow_t;

#endif
