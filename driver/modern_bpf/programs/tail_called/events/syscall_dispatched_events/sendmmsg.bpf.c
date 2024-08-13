// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

extern int LINUX_KERNEL_VERSION __kconfig;

/*=============================== ENTER EVENT ===========================*/

typedef struct sendmmsg_enter_s
{
	uint32_t fd;
	struct mmsghdr *mmh;
	unsigned int vlen;
	struct pt_regs *regs;
} sendmmsg_enter_t;

static long handle_enter(uint32_t index, void *ctx)
{
	sendmmsg_enter_t *data = (sendmmsg_enter_t *)ctx;
	struct mmsghdr mmh;

	if(bpf_probe_read_user((void *)&mmh, bpf_core_type_size(struct mmsghdr), (void *)(data->mmh + index)) != 0)
	{
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMMSG_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, (int64_t)data->fd);

	/* Parameter 2: size (type: PT_UINT32) */
	unsigned long msghdr_pointer = (unsigned long)&mmh.msg_hdr;
	auxmap__store_msghdr_size_param(auxmap, msghdr_pointer);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	/* TODO: Here we don't know if this fd is a socket or not,
	 * since we are in the enter event and the syscall could fail.
	 * This shouldn't be a problem since if it is not a socket fd
	 * the `bpf_probe_read()` call we fail. Probably we have to move it
	 * in the exit event.
	 */
	if(data->fd >= 0)
	{
		/*
		struct sockaddr *usrsockaddr;
		struct msghdr *msg = (struct msghdr*)msghdr_pointer;
		BPF_CORE_READ_USER_INTO(&usrsockaddr, msg, msg_name);
		*/
		auxmap__store_socktuple_param(auxmap, data->fd, OUTBOUND, mmh.msg_hdr.msg_name);
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	return auxmap__try_submit_event(auxmap);
}

SEC("tp_btf/sys_enter")
int BPF_PROG(sendmmsg_e, struct pt_regs *regs, long id)
{
	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);
	sendmmsg_enter_t data = {
		.fd = args[0],
		.mmh = (struct mmsghdr *)args[1],
		.vlen = args[2],
		.regs = regs,
	};

	if(LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 17, 0))
	{
		bpf_loop(data.vlen < 1024 ? data.vlen : 1024, handle_enter, &data, 0);
		return 0;
	}

	struct mmsghdr mmsghdr;

	for(int i = 0; i < data.vlen && i < MAX_IOVCNT; i++)
	{
		handle_enter(i, &data);
	}

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

typedef struct sendmmsg_exit_s
{
	struct mmsghdr *mmh;
	struct pt_regs *regs;
} sendmmsg_exit_t;

static long handle_exit(uint32_t index, void *ctx)
{
	sendmmsg_exit_t *data = (sendmmsg_exit_t *)ctx;
	struct mmsghdr mmh;

	if(bpf_probe_read_user((void *)&mmh, bpf_core_type_size(struct mmsghdr), (void *)(data->mmh + index)) != 0)
	{
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, mmh.msg_len);

	/* In case of failure `bytes_to_read` could be also lower than `snaplen`
	 * but we will discover it directly into `auxmap__store_iovec_data_param`
	 * otherwise we need to extract it now and it has a cost. Here we check just
	 * the return value if the syscall is successful.
	 */
	uint16_t snaplen = maps__get_snaplen();
	// TODO: check sockaddr
	apply_dynamic_snaplen(data->regs, &snaplen, true, NULL);
	if(mmh.msg_len > 0 && snaplen > mmh.msg_len)
	{
		snaplen = mmh.msg_len;
	}

	/* Parameter 2: data (type: PT_BYTEBUF) */
	unsigned long msghdr_pointer = (unsigned long)&mmh.msg_hdr;
	auxmap__store_msghdr_data_param(auxmap, msghdr_pointer, snaplen);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	return auxmap__try_submit_event(auxmap);
}

SEC("tp_btf/sys_exit")
int BPF_PROG(sendmmsg_x, struct pt_regs *regs, long ret)
{
	if(ret < 0)
	{
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[2];
	extract__network_args(args, 2, regs);
	sendmmsg_exit_t data = {
		.mmh = (struct mmsghdr *)args[1],
		.regs = regs,
	};

	if(LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 17, 0))
	{
		bpf_loop(ret < 1024 ? ret : 1024, handle_exit, &data, 0);
		return 0;
	}

	for(int i = 0; i < ret && i < MAX_IOVCNT; i++)
	{
		handle_exit(i, &data);
	}

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
