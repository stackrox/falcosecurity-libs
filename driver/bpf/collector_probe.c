/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#include "quirks.h"

#include <generated/utsrelease.h>
#include <linux/sched.h>
#include <uapi/linux/bpf.h>

// clang-format off
#include "../driver_config.h"
#include "../ppm_events_public.h"
#include "bpf_helpers.h"
#include "types.h"
#include "maps.h"
#include "plumbing_helpers.h"
#include "ring_helpers.h"
#include "filler_helpers.h"
#include "fillers.h"
#include "builtins.h"
// clang-format on

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
__bpf_section("tracepoint/sched/sched_process_fork") int bpf_sched_process_fork(
    struct sched_process_fork_args *ctx) {
  struct sysdig_bpf_settings *settings;
  enum ppm_event_type evt_type;
  struct sys_stash_args args;
  unsigned long *argsp;

  settings = get_bpf_settings();
  if (!settings)
    return 0;

  if (!settings->capture_enabled)
    return 0;

  argsp = __unstash_args(ctx->parent_pid);
  if (!argsp)
    return 0;

  memcpy(&args, argsp, sizeof(args));

  __stash_args(ctx->child_pid, args.args);
  return 0;
}
#endif

static __always_inline int no_args_enter_probe(long id, void *ctx) {
  const struct syscall_evt_pair *sc_evt;
  struct sysdig_bpf_settings *settings;
  enum ppm_event_type evt_type;
  int drop_flags;

  settings = get_bpf_settings();
  if (!settings)
    return 0;

  if (!settings->capture_enabled)
    return 0;

  sc_evt = get_syscall_info(id);
  if (!sc_evt)
    return 0;

  if (sc_evt->flags & UF_USED) {
    evt_type = sc_evt->enter_event_type;
    drop_flags = sc_evt->flags;
  } else {
    evt_type = PPME_GENERIC_E;
    drop_flags = UF_ALWAYS_DROP;
    return 0;
  }

  struct sys_enter_args stack_args;
  stack_args.id = id;

  call_filler(ctx, &stack_args, evt_type, settings, drop_flags);
  return 0;
}

static __always_inline int enter_probe(long id, struct sys_enter_args *ctx) {
  const struct syscall_evt_pair *sc_evt;
  struct sysdig_bpf_settings *settings;
  enum ppm_event_type evt_type;
  int drop_flags;

  settings = get_bpf_settings();
  if (!settings) {
    return 0;
  }

 //  if (!settings->capture_enabled) {
 //    bpf_printk("capture disabled\n");
 //    return 0;
 //  }

  sc_evt = get_syscall_info(id);
  if (!sc_evt) {
    bpf_printk("no event\n");
    return 0;
  }

  if (sc_evt->flags & UF_USED) {
    evt_type = sc_evt->enter_event_type;
    drop_flags = sc_evt->flags;
  } else {
    evt_type = PPME_GENERIC_E;
    drop_flags = UF_ALWAYS_DROP;
    return 0;
  }

	call_filler(ctx, ctx, evt_type, settings, drop_flags);
  return 0;
}

static __always_inline int exit_probe(long id, struct sys_exit_args *ctx) {
  const struct syscall_evt_pair *sc_evt;
  struct sysdig_bpf_settings *settings;
  enum ppm_event_type evt_type;
  int drop_flags;

  settings = get_bpf_settings();
  if (!settings)
    return 0;

  if (!settings->capture_enabled)
    return 0;

  sc_evt = get_syscall_info(id);
  if (!sc_evt)
    return 0;

  if (sc_evt->flags & UF_USED) {
    evt_type = sc_evt->exit_event_type;
    drop_flags = sc_evt->flags;
  } else {
    evt_type = PPME_GENERIC_X;
    drop_flags = UF_ALWAYS_DROP;
    return 0;
  }

  call_filler(ctx, ctx, evt_type, settings, drop_flags);
  return 0;
}

#define PROBE_SIGNATURE(prefix, event, type) \
	__bpf_section("tracepoint/" prefix #event) int bpf_##event(struct type *ctx)

#define PROBE_SIGNATURE_VOID(prefix, event) \
  __bpf_section("tracepoint/" prefix #event) int bpf_##event(void *ctx)

#define COLLECTOR_PROBE(name, id)\
	PROBE_SIGNATURE("syscalls/", sys_enter_##name, sys_enter_args) \
	{                                                              \
		return enter_probe(id, ctx);                           \
	}                                                              \
                                                                       \
	PROBE_SIGNATURE("syscalls/", sys_exit_##name, sys_exit_args)   \
	{                                                              \
		return exit_probe(id, ctx);                            \
	}

#define COLLECTOR_NO_ARGS_PROBE(name, id) \
	PROBE_SIGNATURE_VOID("syscalls/", sys_enter_##name) \
	{                                                   \
		return no_args_enter_probe(id, ctx);        \
	}                                                   \
	PROBE_SIGNATURE_VOID("syscalls/", sys_exit_##name)  \
	{                                                   \
		return exit_probe(id, ctx);                 \
	}

COLLECTOR_PROBE(chdir, __NR_chdir);
COLLECTOR_PROBE(accept, __NR_accept);
COLLECTOR_PROBE(accept4, __NR_accept4);
COLLECTOR_PROBE(clone, __NR_clone);
COLLECTOR_PROBE(close, __NR_close);
COLLECTOR_PROBE(connect, __NR_connect);
COLLECTOR_PROBE(execve, __NR_execve);
COLLECTOR_PROBE(setresgid, __NR_setresgid);
COLLECTOR_PROBE(setresuid, __NR_setresuid);
COLLECTOR_PROBE(setgid, __NR_setgid);
COLLECTOR_PROBE(setuid, __NR_setuid);
COLLECTOR_PROBE(shutdown, __NR_shutdown);
COLLECTOR_PROBE(socket, __NR_socket);
COLLECTOR_PROBE(fchdir, __NR_fchdir);

COLLECTOR_NO_ARGS_PROBE(fork, __NR_fork);
COLLECTOR_NO_ARGS_PROBE(vfork, __NR_vfork);

char kernel_ver[] __bpf_section("kernel_version") = UTS_RELEASE;

char __license[] __bpf_section("license") = "GPL";

char probe_ver[] __bpf_section("probe_version") = PROBE_VERSION;
