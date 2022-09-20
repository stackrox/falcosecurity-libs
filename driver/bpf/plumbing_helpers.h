/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __PLUMBING_HELPERS_H
#define __PLUMBING_HELPERS_H

#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/fdtable.h>

#ifdef CAPTURE_SOCKETCALL
#include <linux/net.h>
#endif

#include "types.h"
#include "builtins.h"

#define _READ(P) ({ typeof(P) _val;					\
		    memset(&_val, 0, sizeof(_val));			\
		    bpf_probe_read_kernel(&_val, sizeof(_val), &P);	\
		    _val;						\
		 })
#define _READ_KERNEL(P) _READ(P)
#define _READ_USER(P) ({ typeof(P) _val;				\
			 memset(&_val, 0, sizeof(_val));		\
			 bpf_probe_read_user(&_val, sizeof(_val), &P);	\
			 _val;						\
		 })

#ifdef BPF_DEBUG
#define bpf_printk(fmt, ...)					\
	do {							\
		char s[] = fmt;					\
		bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__);	\
	} while (0)
#else
#define bpf_printk(fmt, ...)
#endif

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
static __always_inline int __stash_args(unsigned long long id,
					unsigned long *args)
{
	int ret = bpf_map_update_elem(&stash_map, &id, args, BPF_ANY);

	if (ret)
		bpf_printk("error stashing arguments for %d:%d\n", id, ret);

	return ret;
}

static __always_inline int stash_args(unsigned long *args)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __stash_args(id, args);
}

static __always_inline unsigned long *__unstash_args(unsigned long long id)
{
	struct sys_stash_args *args;

	args = bpf_map_lookup_elem(&stash_map, &id);
	if (!args)
		return NULL;

	return args->args;
}

static __always_inline unsigned long *unstash_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __unstash_args(id);
}

static __always_inline void delete_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	bpf_map_delete_elem(&stash_map, &id);
}
#endif

#ifdef CAPTURE_SOCKETCALL

static __always_inline int stash_socketcall_args(unsigned long *args)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;
	int ret = bpf_map_update_elem(&socketcall_args_map, &id, args, BPF_ANY);

	if (ret)
		bpf_printk("error stashing socketcall arguments for %d:%d\n", id, ret);

	return ret;
}

static __always_inline unsigned long *unstash_socketcall_args()
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;
	unsigned long *sargs;

	sargs = bpf_map_lookup_elem(&socketcall_args_map, &id);
	if (!sargs)
		return NULL;

	return sargs;
}

static __always_inline void delete_socketcall_args()
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	bpf_map_delete_elem(&socketcall_args_map, &id);
}

#endif

/* Can be called just from an exit event
 */
static __always_inline long bpf_syscall_get_retval(void *ctx)
{
	struct sys_exit_args *args = (struct sys_exit_args *)ctx;

	return args->ret;
}

/* Can be called from both enter and exit event, id is at the same
 * offset in both struct sys_enter_args and struct sys_exit_args
 */
static __always_inline long bpf_syscall_get_nr(void *ctx)
{
	struct sys_enter_args *args = (struct sys_enter_args *)ctx;
	long id = 0;

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS

	struct pt_regs *regs = (struct pt_regs *)args->regs;

#ifdef CONFIG_X86_64

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/x86/include/asm/syscall.h#L40
	 */	
	id = _READ(regs->orig_ax);

#elif CONFIG_ARM64

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/arm64/include/asm/syscall.h#L23
	 */	
	id = _READ(regs->syscallno);

#elif CONFIG_S390

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/s390/include/asm/syscall.h#L24
	 */
	id = _READ(regs->int_code);
	id = id & 0xffff;

#endif /* CONFIG_X86_64 */

#else

	id = args->id;

#endif /* BPF_SUPPORTS_RAW_TRACEPOINTS */

	return id;
}

#if !defined(BPF_SUPPORTS_RAW_TRACEPOINTS) || defined(CAPTURE_SOCKETCALL)
static __always_inline unsigned long bpf_syscall_get_argument_from_args(unsigned long *args,
									int idx)
{
	unsigned long arg = 0;

	if(idx <= 5)
	{
		arg = args[idx];
	}

	return arg;
}
#endif

static __always_inline unsigned long bpf_syscall_get_argument_from_ctx(void *ctx,
								       int idx)
{
	unsigned long arg = 0;

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS

	struct sys_enter_args *args = (struct sys_enter_args *)ctx;
	struct pt_regs *regs = (struct pt_regs *)args->regs;

#ifdef CONFIG_X86_64

	/* See here for the definition:
	 * https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h#L75-L87
	 */
	switch (idx) {
	case 0:
		arg = _READ(regs->di);
		break;
	case 1:
		arg = _READ(regs->si);
		break;
	case 2:
		arg = _READ(regs->dx);
		break;
	case 3:
		arg = _READ(regs->r10);
		break;
	case 4:
		arg = _READ(regs->r8);
		break;
	case 5:
		arg = _READ(regs->r9);
		break;
	default:
		arg = 0;
	}

#elif CONFIG_ARM64

	/* See here for the definition:
	 * https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h#L166-L178 
	 */
	struct user_pt_regs *user_regs = (struct user_pt_regs *)args->regs;
	switch (idx) {
	case 0:
		arg = _READ(regs->orig_x0);
		break;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		arg = _READ(user_regs->regs[idx]);
		break;
	default:
		arg = 0;
	}

#elif CONFIG_S390
	
	/* See here for the definition:
	 * https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h#L132-L144
	 */
	user_pt_regs *user_regs = (user_pt_regs *)args->regs;
	switch (idx) {
	case 0:
		arg = _READ(regs->orig_gpr2);
		break;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		arg = _READ(user_regs->gprs[idx+2]);
		break;
	default:
		arg = 0;
	}

#endif /* CONFIG_X86_64 */

#else

	unsigned long *args = unstash_args();
	if (args)
		arg = bpf_syscall_get_argument_from_args(args, idx);
	else
		arg = 0;
		
#endif /* BPF_SUPPORTS_RAW_TRACEPOINTS */

	return arg;
}

static __always_inline unsigned long bpf_syscall_get_argument(struct filler_data *data,
							      int idx)
{
#if defined(CAPTURE_SOCKETCALL)
	if (data->state->tail_ctx.is_socketcall) {
		unsigned long *sargs = unstash_socketcall_args();
		if (sargs == NULL)
			return 0;
		return bpf_syscall_get_argument_from_args(sargs, idx);
	}
#endif
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	return bpf_syscall_get_argument_from_ctx(data->ctx, idx);
#else
	return bpf_syscall_get_argument_from_args(data->args, idx);
#endif
}

static __always_inline char *get_frame_scratch_area(unsigned int cpu)
{
	char *scratchp;

	scratchp = bpf_map_lookup_elem(&frame_scratch_map, &cpu);
	if (!scratchp)
		bpf_printk("frame scratch NULL\n");

	return scratchp;
}

static __always_inline char *get_tmp_scratch_area(unsigned int cpu)
{
	char *scratchp;

	scratchp = bpf_map_lookup_elem(&tmp_scratch_map, &cpu);
	if (!scratchp)
		bpf_printk("tmp scratch NULL\n");

	return scratchp;
}

static __always_inline const struct syscall_evt_pair *get_syscall_info(int id)
{
	const struct syscall_evt_pair *p =
			bpf_map_lookup_elem(&syscall_table, &id);

	if (!p)
		bpf_printk("no syscall_info for %d\n", id);

	return p;
}

static __always_inline bool is_syscall_interesting(int id)
{
	bool *enabled = bpf_map_lookup_elem(&interesting_syscalls_table, &id);

	if (!enabled)
	{
		bpf_printk("no syscall_info for %d\n", id);
		return false;
	}

	return *enabled;
}

static __always_inline const struct ppm_event_info *get_event_info(enum ppm_event_type event_type)
{
	const struct ppm_event_info *e =
		bpf_map_lookup_elem(&event_info_table, &event_type);

	if (!e)
		bpf_printk("no event info for %d\n", event_type);

	return e;
}

static __always_inline const struct ppm_event_entry *get_event_filler_info(enum ppm_event_type event_type)
{
	const struct ppm_event_entry *e;

	e = bpf_map_lookup_elem(&fillers_table, &event_type);
	if (!e)
		bpf_printk("no filler info for %d\n", event_type);

	return e;
}

static __always_inline struct scap_bpf_settings *get_bpf_settings(void)
{
	struct scap_bpf_settings *settings;
	int id = 0;

	settings = bpf_map_lookup_elem(&settings_map, &id);
	if (!settings)
		bpf_printk("settings NULL\n");

	return settings;
}

static __always_inline struct scap_bpf_per_cpu_state *get_local_state(unsigned int cpu)
{
	struct scap_bpf_per_cpu_state *state;

	state = bpf_map_lookup_elem(&local_state_map, &cpu);
	if (!state)
		bpf_printk("state NULL\n");

	return state;
}

static __always_inline bool acquire_local_state(struct scap_bpf_per_cpu_state *state)
{
	if (state->in_use) {
		bpf_printk("acquire_local_state: already in use\n");
		return false;
	}

	state->in_use = true;
	return true;
}

static __always_inline bool release_local_state(struct scap_bpf_per_cpu_state *state)
{
	if (!state->in_use) {
		bpf_printk("release_local_state: already not in use\n");
		return false;
	}

	state->in_use = false;
	return true;
}

static __always_inline int init_filler_data(void *ctx,
					    struct filler_data *data,
					    bool is_syscall)
{
	unsigned int cpu;

	data->ctx = ctx;

	data->settings = get_bpf_settings();
	if (!data->settings)
		return PPM_FAILURE_BUG;

	cpu = bpf_get_smp_processor_id();

	data->buf = get_frame_scratch_area(cpu);
	if (!data->buf)
		return PPM_FAILURE_BUG;

	data->state = get_local_state(cpu);
	if (!data->state)
		return PPM_FAILURE_BUG;

	data->tmp_scratch = get_tmp_scratch_area(cpu);
	if (!data->tmp_scratch)
		return PPM_FAILURE_BUG;

	data->evt = get_event_info(data->state->tail_ctx.evt_type);
	if (!data->evt)
		return PPM_FAILURE_BUG;

	data->filler_info = get_event_filler_info(data->state->tail_ctx.evt_type);
	if (!data->filler_info)
		return PPM_FAILURE_BUG;

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
	if (is_syscall) {
		data->args = unstash_args();
		if (!data->args)
			return PPM_SKIP_EVENT;
	}
#endif

	data->curarg_already_on_frame = false;
	data->fd = -1;

	return PPM_SUCCESS;
}

#ifdef CAPTURE_SOCKETCALL

static __always_inline enum ppm_event_type parse_socketcall(int socketcall_id)
{
	switch (socketcall_id) {
	case SYS_SOCKET:
		return PPME_SOCKET_SOCKET_E;
	case SYS_BIND:
		return PPME_SOCKET_BIND_E;
	case SYS_CONNECT:
		return PPME_SOCKET_CONNECT_E;
	case SYS_LISTEN:
		return PPME_SOCKET_LISTEN_E;
	case SYS_ACCEPT:
		return PPME_SOCKET_ACCEPT_5_E;
	case SYS_GETSOCKNAME:
		return PPME_SOCKET_GETSOCKNAME_E;
	case SYS_GETPEERNAME:
		return PPME_SOCKET_GETPEERNAME_E;
	case SYS_SOCKETPAIR:
		return PPME_SOCKET_SOCKETPAIR_E;
	case SYS_SEND:
		return PPME_SOCKET_SEND_E;
	case SYS_SENDTO:
		return PPME_SOCKET_SENDTO_E;
	case SYS_RECV:
		return PPME_SOCKET_RECV_E;
	case SYS_RECVFROM:
		return PPME_SOCKET_RECVFROM_E;
	case SYS_SHUTDOWN:
		return PPME_SOCKET_SHUTDOWN_E;
	case SYS_SETSOCKOPT:
		return PPME_SOCKET_SETSOCKOPT_E;
	case SYS_GETSOCKOPT:
		return PPME_SOCKET_GETSOCKOPT_E;
	case SYS_SENDMSG:
		return PPME_SOCKET_SENDMSG_E;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	case SYS_SENDMMSG:
		return PPME_SOCKET_SENDMMSG_E;
#endif
	case SYS_RECVMSG:
		return PPME_SOCKET_RECVMSG_E;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	case SYS_RECVMMSG:
		return PPME_SOCKET_RECVMMSG_E;
#endif
	case SYS_ACCEPT4:
		return PPME_SOCKET_ACCEPT4_5_E;
	default:
		return PPME_GENERIC_E;
	}

	return PPME_GENERIC_E;
}

static __always_inline int __bpf_read_socketcall_args(void *dest, void *src, int sc_id)
{
	/* BPF verifier:
	 *
	 * Using nas[socketcall_id] causes an exception due to arithmetic operations
	 * on the size argument. Therefore, use a switch statement instead, and directly
	 * specify the number of bytes (arguments) to read.
	 */
#define AL(x) ((x) * sizeof(unsigned long))
	switch (sc_id) {
	case 0:
		return 0;
	case SYS_SOCKET:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_BIND:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_CONNECT:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_LISTEN:
		return bpf_probe_read_user(dest, AL(2), src);
	case SYS_ACCEPT:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_GETSOCKNAME:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_GETPEERNAME:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_SOCKETPAIR:
		return bpf_probe_read_user(dest, AL(4), src);
	case SYS_SEND:
		return bpf_probe_read_user(dest, AL(4), src);
	case SYS_RECV:
		return bpf_probe_read_user(dest, AL(4), src);
	case SYS_SENDTO:
		return bpf_probe_read_user(dest, AL(6), src);
	case SYS_RECVFROM:
		return bpf_probe_read_user(dest, AL(6), src);
	case SYS_SHUTDOWN:
		return bpf_probe_read_user(dest, AL(2), src);
	case SYS_SETSOCKOPT:
		return bpf_probe_read_user(dest, AL(5), src);
	case SYS_GETSOCKOPT:
		return bpf_probe_read_user(dest, AL(5), src);
	case SYS_SENDMSG:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_RECVMSG:
		return bpf_probe_read_user(dest, AL(3), src);
	case SYS_ACCEPT4:
		return bpf_probe_read_user(dest, AL(4), src);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	case SYS_RECVMMSG:
		return bpf_probe_read_user(dest, AL(5), src);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	case SYS_SENDMMSG:
		return bpf_probe_read_user(dest, AL(4), src);
#endif
	default:
		return -1;
	};
#undef AL

	return 0;
}

static __always_inline bool handle_socketcall(void *ctx,
					      struct scap_bpf_per_cpu_state *state,
					      enum ppm_event_type*evt_type,
					      enum syscall_flags *drop_flags)
{
	int socketcall_id, id;
	unsigned long scargs;
	unsigned long args[6];
	enum ppm_event_type tet;

	id = bpf_syscall_get_nr(ctx);
	if (id != __NR_socketcall)
		return false;

	socketcall_id = bpf_syscall_get_argument_from_ctx(ctx, 0);
	tet = parse_socketcall(socketcall_id);
	if (tet == PPME_GENERIC_E)
		return false;

	if (*evt_type == PPME_GENERIC_E)
		*evt_type = tet;
	else
		*evt_type = tet + 1;	/* exit event */

	scargs = bpf_syscall_get_argument_from_ctx(ctx, 1);
	memset(args, 0, sizeof(args));
	if (__bpf_read_socketcall_args(args, (void *)scargs, socketcall_id))
		return true;	/* event will likely be dropped */
	stash_socketcall_args(args);

	*drop_flags = UF_NEVER_DROP;
	state->tail_ctx.is_socketcall = true;
	state->tail_ctx.evt_type = *evt_type;

	return false;
}

#endif	/* CAPTURE_SOCKETCALL */

static __always_inline int bpf_test_bit(int nr, unsigned long *addr)
{
	return 1UL & (_READ(addr[BIT_WORD(nr)]) >> (nr & (BITS_PER_LONG - 1)));
}

static __always_inline bool drop_event(void *ctx,
				       struct scap_bpf_per_cpu_state *state,
				       enum ppm_event_type evt_type,
				       struct scap_bpf_settings *settings,
				       enum syscall_flags drop_flags)
{
	if (!settings->dropping_mode)
		return false;

	switch (evt_type) {
	case PPME_SYSCALL_CLOSE_X:
	case PPME_SOCKET_BIND_X: {
		long ret = bpf_syscall_get_retval(ctx);

		if (ret < 0)
			return true;

		break;
	}
	case PPME_SYSCALL_CLOSE_E: {
		struct sys_enter_args *args;
		struct files_struct *files;
		struct task_struct *task;
		unsigned long *open_fds;
		struct fdtable *fdt;
		int close_fd;
		int max_fds;

		close_fd = bpf_syscall_get_argument_from_ctx(ctx, 0);
		if (close_fd < 0)
			return true;

		task = (struct task_struct *)bpf_get_current_task();
		if (!task)
			break;

		files = _READ(task->files);
		if (!files)
			break;

		fdt = _READ(files->fdt);
		if (!fdt)
			break;

		max_fds = _READ(fdt->max_fds);
		if (close_fd >= max_fds)
			return true;

		open_fds = _READ(fdt->open_fds);
		if (!open_fds)
			break;

		if (!bpf_test_bit(close_fd, open_fds))
			return true;

		break;
	}
	case PPME_SYSCALL_FCNTL_E:
	case PPME_SYSCALL_FCNTL_X: {
		long cmd = bpf_syscall_get_argument_from_ctx(ctx, 1);

		if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC)
			return true;

		break;
	}
	default:
		break;
	}

	if (drop_flags & UF_NEVER_DROP)
		return false;

	if (drop_flags & UF_ALWAYS_DROP)
		return true;

	if (state->tail_ctx.ts % 1000000000 >= 1000000000 /
	    settings->sampling_ratio) {
		if (!settings->is_dropping) {
			settings->is_dropping = true;
			state->tail_ctx.evt_type = PPME_DROP_E;
			return false;
		}

		return true;
	}

	if (settings->is_dropping) {
		settings->is_dropping = false;
		state->tail_ctx.evt_type = PPME_DROP_X;
		return false;
	}

	return false;
}

static __always_inline void reset_tail_ctx(struct scap_bpf_per_cpu_state *state,
					   enum ppm_event_type evt_type,
					   unsigned long long ts)
{
	state->tail_ctx.evt_type = evt_type;
	state->tail_ctx.ts = ts;
	state->tail_ctx.curarg = 0;
	state->tail_ctx.curoff = 0;
	state->tail_ctx.len = 0;
	state->tail_ctx.prev_res = 0;
#ifdef CAPTURE_SOCKETCALL
	state->tail_ctx.is_socketcall = false;
#endif
}

static __always_inline void call_filler(void *ctx,
					void *stack_ctx,
					enum ppm_event_type evt_type,
					struct scap_bpf_settings *settings,
					enum syscall_flags drop_flags)
{
	const struct ppm_event_entry *filler_info;
	struct scap_bpf_per_cpu_state *state;
	unsigned long long pid;
	unsigned long long ts;
	unsigned int cpu;

	cpu = bpf_get_smp_processor_id();

	state = get_local_state(cpu);
	if (!state)
		return;

	if (!acquire_local_state(state))
		return;

	if (cpu == 0 && state->hotplug_cpu != 0) {
		evt_type = PPME_CPU_HOTPLUG_E;
		drop_flags = UF_NEVER_DROP;
	}

	ts = settings->boot_time + bpf_ktime_get_boot_ns();
	reset_tail_ctx(state, evt_type, ts);

#ifdef CAPTURE_SOCKETCALL
	/* Handle and extract network event based on socketcall multiplexer */
	if (evt_type == PPME_GENERIC_E || evt_type == PPME_GENERIC_X)
		if (handle_socketcall(ctx, state, &evt_type, &drop_flags))
			goto cleanup;
#endif

	/* drop_event can change state->tail_ctx.evt_type */
	if (drop_event(stack_ctx, state, evt_type, settings, drop_flags))
		goto cleanup;

	++state->n_evts;

	filler_info = get_event_filler_info(state->tail_ctx.evt_type);
	if (!filler_info)
		goto cleanup;

	bpf_tail_call(ctx, &tail_map, filler_info->filler_id);
	bpf_printk("Can't tail call filler evt=%d, filler=%d\n",
		   state->tail_ctx.evt_type,
		   filler_info->filler_id);

cleanup:
#ifdef CAPTURE_SOCKETCALL
	if (state->tail_ctx.is_socketcall)
		delete_socketcall_args();
#endif
	release_local_state(state);
}

#endif
