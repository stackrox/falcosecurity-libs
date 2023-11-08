
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

#define ATTACH(name, err)                                                      \
	if(((err) = generic_attach_program(#name,                              \
					   g_state.skel->progs.name,         \
					   &g_state.skel->links.name)) != 0) \
	{                                                                      \
		return (err);                                                  \
	}

#define DETACH(name, err)                                                      \
	if(((err) = generic_detach_program(#name,                              \
					   &g_state.skel->links.name)) != 0) \
	{                                                                      \
		return (err);                                                  \
	}

static int handle_syscall_enter_programs(bool enable)
{
	int result = 0;

	if(enable)
	{
		ATTACH(sys_enter_chdir, result);
	}
	else
	{
		DETACH(sys_enter_chdir, result);
	}

	return result;
}

static int handle_syscall_exit_programs(bool enable)
{
	int result = 0;

	if(enable)
	{
		ATTACH(sys_exit_chdir, result);
	}
	else
	{
		DETACH(sys_exit_chdir, result);
	}

	return result;
}

int pman_update_single_program(int tp, bool enabled)
{
	switch(tp)
	{
	case SYS_ENTER:
		// attach all sys_enter_* probes for individual system calls
		return handle_syscall_enter_programs(enabled);
	case SYS_EXIT:
		return handle_syscall_exit_programs(enabled);
	}

	return 0;
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
