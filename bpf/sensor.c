//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

enum event_type {
	EVENT_EXEC = 1,
	EVENT_EXIT = 2,
	EVENT_OPEN = 3,
};

struct event {
	u32 type;
	u32 pid;
	u32 ppid;
	u32 root_pid;
	s32 exit_code;
	char comm[TASK_COMM_LEN];
};

#define PATH_HINT_LEN 256

struct open_event {
	u32 pid;
	u32 root_pid;
	s32 fd;
	s32 flags;
	char comm[TASK_COMM_LEN];
	char path_hint[PATH_HINT_LEN];
};

struct open_scratch {
	char path_hint[PATH_HINT_LEN];
	s32 flags;
};

struct chmod_event {
	u32 pid;
	u32 root_pid;
	u32 mode;
	char comm[TASK_COMM_LEN];
	char path[PATH_HINT_LEN];
};

// Tracepoint context structs matching kernel format definitions.
// Fields before the tracepoint-specific fields (common_type, common_flags,
// common_preempt_count, common_pid) are at fixed offsets handled by the
// tracepoint infrastructure — we skip them by starting our struct at the
// first tracepoint-specific field.

// No manual tp_fork_ctx struct — kernel 6.12+ changed parent_comm/child_comm
// from char[16] to __data_loc char[], shifting field offsets. We use CO-RE
// (BPF_CORE_READ on trace_event_raw_sched_process_fork from vmlinux.h) so the
// loader relocates parent_pid/child_pid offsets for the running kernel.

struct tp_exit_ctx {
	u64 __pad;
	char comm[16];
	s32 pid;
	s32 prio;
};

struct tp_exec_ctx {
	u64 __pad;
	u32 filename_loc; // __data_loc
	s32 pid;
	s32 old_pid;
};

struct tp_fchmodat_ctx {
	u64 __pad;
	s32 __syscall_nr;
	u32 __pad2;
	u64 dfd;
	const char *filename;
	u64 mode;
};

struct tp_openat_enter_ctx {
	u64 __pad;
	s32 __syscall_nr;
	u32 __pad2;
	u64 dfd;
	const char *filename;
	u64 flags;
	u64 mode;
};

struct tp_openat_exit_ctx {
	u64 __pad;
	s32 __syscall_nr;
	u32 __pad2;
	s64 ret;
};

// pid -> agent_root_pid mapping for subtree tracking.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u32);
} pid_to_root SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} open_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct open_scratch);
} open_scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} chmod_events SEC(".maps");

#define S_ISUID 04000
#define S_ISGID 02000

// Tracepoint: sched/sched_process_fork
// If parent is in a tracked subtree, add child to the same subtree.
// Uses CO-RE reads for parent_pid/child_pid because kernel 6.12+ changed
// the tracepoint layout (parent_comm/child_comm went from char[16] to
// __data_loc char[]), shifting field offsets. BPF_CORE_READ lets the
// loader resolve the correct offsets for the running kernel.
SEC("tracepoint/sched/sched_process_fork")
int tp_sched_process_fork(void *ctx) {
	struct trace_event_raw_sched_process_fork *raw = ctx;
	u32 parent_pid = BPF_CORE_READ(raw, parent_pid);
	u32 child_pid = BPF_CORE_READ(raw, child_pid);

	u32 *root = bpf_map_lookup_elem(&pid_to_root, &parent_pid);
	if (root) {
		u32 root_val = *root;
		bpf_map_update_elem(&pid_to_root, &child_pid, &root_val, BPF_ANY);
	}
	return 0;
}

// Tracepoint: sched/sched_process_exit
// If pid is tracked, emit EXIT event and remove from map.
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct tp_exit_ctx *ctx) {
	u32 pid = ctx->pid;

	u32 *root = bpf_map_lookup_elem(&pid_to_root, &pid);
	if (!root)
		return 0;

	struct event ev = {};
	ev.type = EVENT_EXIT;
	ev.pid = pid;
	ev.root_pid = *root;

	// Read exit_code from current task via BPF helper.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	ev.exit_code = BPF_CORE_READ(task, exit_code) >> 8;

	bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

	bpf_map_delete_elem(&pid_to_root, &pid);
	return 0;
}

// Tracepoint: sched/sched_process_exec
// Fires AFTER exec completes, so /proc reads reflect the new binary.
// For pids already in a tracked subtree, include the root_pid so userspace
// can detect agent children that exec into a new agent binary (promotion).
SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct tp_exec_ctx *ctx) {
	u32 pid = ctx->pid;

	struct event ev = {};
	ev.type = EVENT_EXEC;
	ev.pid = pid;
	bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

	// Read ppid from current task.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	ev.ppid = (u32)BPF_CORE_READ(task, real_parent, tgid);

	u32 *root = bpf_map_lookup_elem(&pid_to_root, &pid);
	if (root)
		ev.root_pid = *root;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

// Tracepoint: syscalls/sys_enter_openat
// Save path_hint and flags to scratch map for PIDs in the agent subtree.
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct tp_openat_enter_ctx *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;

	// Only track opens from the agent subtree.
	if (!bpf_map_lookup_elem(&pid_to_root, &pid))
		return 0;

	struct open_scratch scratch = {};
	scratch.flags = (s32)ctx->flags;
	bpf_probe_read_user_str(&scratch.path_hint, sizeof(scratch.path_hint),
				ctx->filename);

	bpf_map_update_elem(&open_scratch_map, &pid_tgid, &scratch, BPF_ANY);
	return 0;
}

// Tracepoint: syscalls/sys_exit_openat
// Read scratch entry, emit open_event with the returned fd.
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct tp_openat_exit_ctx *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();

	struct open_scratch *scratch = bpf_map_lookup_elem(&open_scratch_map,
							   &pid_tgid);
	if (!scratch)
		return 0;

	u32 pid = pid_tgid >> 32;
	u32 *root = bpf_map_lookup_elem(&pid_to_root, &pid);
	if (!root) {
		bpf_map_delete_elem(&open_scratch_map, &pid_tgid);
		return 0;
	}

	struct open_event oev = {};
	oev.pid = pid;
	oev.root_pid = *root;
	oev.fd = (s32)ctx->ret;
	oev.flags = scratch->flags;
	bpf_get_current_comm(&oev.comm, sizeof(oev.comm));
	__builtin_memcpy(&oev.path_hint, scratch->path_hint,
			 sizeof(oev.path_hint));

	bpf_perf_event_output(ctx, &open_events, BPF_F_CURRENT_CPU,
			      &oev, sizeof(oev));

	bpf_map_delete_elem(&open_scratch_map, &pid_tgid);
	return 0;
}

// Tracepoint: syscalls/sys_enter_fchmodat
// Detect setuid/setgid bit setting in the agent subtree.
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tp_sys_enter_fchmodat(struct tp_fchmodat_ctx *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;

	u32 *root = bpf_map_lookup_elem(&pid_to_root, &pid);
	if (!root)
		return 0;

	u32 mode = (u32)ctx->mode;
	if (!(mode & S_ISUID) && !(mode & S_ISGID))
		return 0;

	struct chmod_event cev = {};
	cev.pid = pid;
	cev.root_pid = *root;
	cev.mode = mode;
	bpf_get_current_comm(&cev.comm, sizeof(cev.comm));
	bpf_probe_read_user_str(&cev.path, sizeof(cev.path), ctx->filename);

	bpf_perf_event_output(ctx, &chmod_events, BPF_F_CURRENT_CPU,
			      &cev, sizeof(cev));
	return 0;
}
