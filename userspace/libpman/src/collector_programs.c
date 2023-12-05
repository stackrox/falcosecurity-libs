
#include <stdio.h>
#include <feature_gates.h>
#include <ppm_tp.h>
#include <stdbool.h>
#include "state.h"
#include <libpman.h>

static int update_all_programs(bool enabled)
{
	for(int i = 0; i < TP_VAL_MAX; i++)
	{
		int ret = pman_update_single_program(i, enabled);
		if(ret != 0)
		{
			return ret;
		}
	}

	return 0;
}

static int generic_attach_program(const char *name, struct bpf_program *program, struct bpf_link **link)
{
	if(*link != NULL)
	{
		// this program is already attached
		return 0;
	}

	*link = bpf_program__attach(program);
	if(*link == NULL)
	{
		char error_buf[256] = {0};
		snprintf(error_buf, 256, "failed to attach %s", name);
		pman_print_error(error_buf);
		return errno;
	}

	return 0;
}

static int generic_detach_program(const char *name, struct bpf_link **link)
{
	if(*link != NULL)
	{
		if(bpf_link__destroy(*link) != 0)
		{
			char error_buf[256] = {0};
			snprintf(error_buf, 256, "failed to detach %s", name);
			pman_print_error(error_buf);

			return errno;
		}

		*link = NULL;
	}

	return 0;
}

#define ATTACH(name, err)                                                    \
	if(((err) = generic_attach_program(#name,                            \
					   g_state.skel->progs.name,         \
					   &g_state.skel->links.name)) != 0) \
	{                                                                    \
		return (err);                                                \
	}

#define DETACH(name, err)                                                    \
	if(((err) = generic_detach_program(#name,                            \
					   &g_state.skel->links.name)) != 0) \
	{                                                                    \
		return (err);                                                \
	}

static int handle_syscall_enter_programs(bool enable)
{
	int result = 0;

	if(enable)
	{
		ATTACH(sys_enter_chdir, result);
#ifdef __NR_accept
		ATTACH(sys_enter_accept, result);
#endif
		ATTACH(sys_enter_accept4, result);
		ATTACH(sys_enter_clone, result);
		ATTACH(sys_enter_close, result);
		ATTACH(sys_enter_connect, result);
		ATTACH(sys_enter_execve, result);
		ATTACH(sys_enter_getsockopt, result);
		ATTACH(sys_enter_setresgid, result);
		ATTACH(sys_enter_setresuid, result);
		ATTACH(sys_enter_setgid, result);
		ATTACH(sys_enter_setuid, result);
		ATTACH(sys_enter_shutdown, result);
		ATTACH(sys_enter_socket, result);
		// #ifdef CAPTURE_SOCKETCALL
		//		// The socketcall handling in driver/bpf/plumbing_helpers.h will filter
		//		// socket calls based on those mentioned here.  Therefore
		//		// socket calls needs to be synchronized.
		//		ATTACH(sys_enter_socketcall, result);
		// #endif
		ATTACH(sys_enter_fchdir, result);
		ATTACH(sys_enter_fork, result);
		ATTACH(sys_enter_vfork, result);
	}
	else
	{
		DETACH(sys_enter_chdir, result);
#ifdef __NR_accept
		DETACH(sys_enter_accept, result);
#endif
		DETACH(sys_enter_accept4, result);
		DETACH(sys_enter_clone, result);
		DETACH(sys_enter_close, result);
		DETACH(sys_enter_connect, result);
		DETACH(sys_enter_execve, result);
		DETACH(sys_enter_getsockopt, result);
		DETACH(sys_enter_setresgid, result);
		DETACH(sys_enter_setresuid, result);
		DETACH(sys_enter_setgid, result);
		DETACH(sys_enter_setuid, result);
		DETACH(sys_enter_shutdown, result);
		DETACH(sys_enter_socket, result);
		// #ifdef CAPTURE_SOCKETCALL
		//		// The socketcall handling in driver/bpf/plumbing_helpers.h will filter
		//		// socket calls based on those mentioned here.  Therefore
		//		// socket calls needs to be synchronized.
		//		DETACH(sys_enter_socketcall, result);
		// #endif
		DETACH(sys_enter_fchdir, result);
		DETACH(sys_enter_fork, result);
		DETACH(sys_enter_vfork, result);
	}

	return result;
}

static int handle_syscall_exit_programs(bool enable)
{
	int result = 0;

	if(enable)
	{
		ATTACH(sys_exit_chdir, result);
#ifdef __NR_accept
		ATTACH(sys_exit_accept, result);
#endif
		ATTACH(sys_exit_accept4, result);
		ATTACH(sys_exit_clone, result);
		ATTACH(sys_exit_close, result);
		ATTACH(sys_exit_connect, result);
		ATTACH(sys_exit_execve, result);
		ATTACH(sys_exit_getsockopt, result);
		ATTACH(sys_exit_setresgid, result);
		ATTACH(sys_exit_setresuid, result);
		ATTACH(sys_exit_setgid, result);
		ATTACH(sys_exit_setuid, result);
		ATTACH(sys_exit_shutdown, result);
		ATTACH(sys_exit_socket, result);
		// #ifdef CAPTURE_SOCKETCALL
		//		// The socketcall handling in driver/bpf/plumbing_helpers.h will filter
		//		// socket calls based on those mentioned here.  Therefore
		//		// socket calls needs to be synchronized.
		//		ATTACH(sys_exit_socketcall, result);
		// #endif
		ATTACH(sys_exit_fchdir, result);
		ATTACH(sys_exit_fork, result);
		ATTACH(sys_exit_vfork, result);
	}
	else
	{
		DETACH(sys_exit_chdir, result);
#ifdef __NR_accept
		DETACH(sys_exit_accept, result);
#endif
		DETACH(sys_exit_accept4, result);
		DETACH(sys_exit_clone, result);
		DETACH(sys_exit_close, result);
		DETACH(sys_exit_connect, result);
		DETACH(sys_exit_execve, result);
		DETACH(sys_exit_getsockopt, result);
		DETACH(sys_exit_setresgid, result);
		DETACH(sys_exit_setresuid, result);
		DETACH(sys_exit_setgid, result);
		DETACH(sys_exit_setuid, result);
		DETACH(sys_exit_shutdown, result);
		DETACH(sys_exit_socket, result);
		// #ifdef CAPTURE_SOCKETCALL
		//		// The socketcall handling in driver/bpf/plumbing_helpers.h will filter
		//		// socket calls based on those mentioned here.  Therefore
		//		// socket calls needs to be synchronized.
		//		DETACH(sys_exit_socketcall, result);
		// #endif
		DETACH(sys_exit_fchdir, result);
		DETACH(sys_exit_fork, result);
		DETACH(sys_exit_vfork, result);
	}

	return result;
}

int pman_update_single_program(int tp, bool enabled)
{
	int result = 0;
	switch(tp)
	{
	case SYS_ENTER:
		// attach all sys_enter_* probes for individual system calls
		return handle_syscall_enter_programs(enabled);
	case SYS_EXIT:
		return handle_syscall_exit_programs(enabled);
	case SCHED_PROC_EXIT:
		if(enabled)
		{
			ATTACH(sched_proc_exit, result);
		}
		else
		{
			DETACH(sched_proc_exit, result);
		}
	case SCHED_SWITCH:
		if(enabled)
		{
			ATTACH(sched_switch, result);
		}
		else
		{
			DETACH(sched_switch, result);
		}
		break;

#ifdef CAPTURE_SCHED_PROC_EXEC
	case SCHED_PROC_EXEC:
		if(enabled)
		{
			ATTACH(sched_proc_exec, result);
		}
		else
		{
			DETACH(sched_proc_exec, result);
		}
		break;
#endif

#ifdef CAPTURE_SCHED_PROC_FORK
	case SCHED_PROC_FORK:
		if(enabled)
		{
			ATTACH(sched_proc_fork, result);
		}
		else
		{
			DETACH(sched_proc_fork, result);
		}
		break;
#endif

#ifdef CAPTURE_PAGE_FAULTS
	case PAGE_FAULT_USER:
		if(enabled)
		{
			ATTACH(pf_user, result);
		}
		else
		{
			DETACH(pf_user, result);
		}
		break;

	case PAGE_FAULT_KERN:
		if(enabled)
		{
			ATTACH(pf_kernel, result);
		}
		else
		{
			DETACH(pf_kernel, result);
		}
		break;
#endif

	case SIGNAL_DELIVER:
		if(enabled)
		{
			ATTACH(signal_deliver, result);
		}
		else
		{
			DETACH(signal_deliver, result);
		}
		break;

	default:
		/* Do nothing right now. */
		break;
	}

	return result;
}

int pman_attach_all_programs()
{
	return update_all_programs(true);
}

int pman_detach_all_programs()
{
	return update_all_programs(false);
}

/**
 * We do not have a syscall_enter or exit dispatcher to attach,
 * so simply return, to indicate success.
 */
int pman_attach_syscall_exit_dispatcher(void) { return 0; }
int pman_detach_syscall_exit_dispatcher(void) { return 0; }
int pman_attach_syscall_enter_dispatcher(void) { return 0; }
int pman_detach_syscall_enter_dispatcher(void) { return 0; }
