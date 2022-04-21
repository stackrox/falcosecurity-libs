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

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
#define BPF_PROBE(prefix, event, type)                                         \
  __bpf_section(TP_NAME #event) int bpf_##event(struct type *ctx)
#else
#define BPF_PROBE(prefix, event, type)                                         \
  __bpf_section(TP_NAME prefix #event) int bpf_##event(struct type *ctx)
#endif

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
__bpf_section(TP_NAME "sched/sched_process_fork") int bpf_sched_process_fork(
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

static __always_inline int enter_probe(struct sys_enter_args *ctx) {
  const struct syscall_evt_pair *sc_evt;
  struct sysdig_bpf_settings *settings;
  enum ppm_event_type evt_type;
  int drop_flags;
  long id;

  settings = get_bpf_settings();
  if (!settings)
    return 0;

  if (!settings->capture_enabled)
    return 0;

  id = bpf_syscall_get_nr(ctx);
  if (id < 0 || id >= SYSCALL_TABLE_SIZE)
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

  call_filler(ctx, ctx, evt_type, settings, drop_flags);
  return 0;
}

static __always_inline int exit_probe(struct sys_exit_args *ctx) {
  const struct syscall_evt_pair *sc_evt;
  struct sysdig_bpf_settings *settings;
  enum ppm_event_type evt_type;
  int drop_flags;
  long id;

  settings = get_bpf_settings();
  if (!settings)
    return 0;

  if (!settings->capture_enabled)
    return 0;

  id = bpf_syscall_get_nr(ctx);
  if (id < 0 || id >= SYSCALL_TABLE_SIZE)
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

#define COLLECTOR_PROBE(name)                                               \
  PROBE_SIGNATURE("syscalls/", sys_enter_##name, sys_enter_args) {          \
    return enter_probe(ctx);                                                \
  }                                                                         \
                                                                            \
  PROBE_SIGNATURE("syscalls/", sys_exit_##name, sys_exit_args) {            \
    return exit_probe(ctx);                                                 \
  }

COLLECTOR_PROBE(chdir);
COLLECTOR_PROBE(accept);
COLLECTOR_PROBE(clone);
COLLECTOR_PROBE(close);
COLLECTOR_PROBE(connect);
COLLECTOR_PROBE(execve);
COLLECTOR_PROBE(setresgid);
COLLECTOR_PROBE(setresuid);
COLLECTOR_PROBE(setgid);
COLLECTOR_PROBE(setuid);
COLLECTOR_PROBE(shutdown);
COLLECTOR_PROBE(socket);
COLLECTOR_PROBE(fchdir);

// COLLECTOR_PROBE(fork, __NR_fork);
// COLLECTOR_PROBE(vfork, __NR_vfork);

char kernel_ver[] __bpf_section("kernel_version") = UTS_RELEASE;

char __license[] __bpf_section("license") = "GPL";

char probe_ver[] __bpf_section("probe_version") = PROBE_VERSION;
