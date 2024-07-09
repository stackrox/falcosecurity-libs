// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(sendmmsg_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	struct mmsghdr mmsghdr;
	struct mmsghdr *mmsghdr_pointer = (struct mmsghdr *)args[1];
	unsigned int vlen = args[2];

	for (int i = 0; i < vlen && i < 16; i++)
	{
		if (bpf_probe_read_user((void *)&mmsghdr, bpf_core_type_size(struct mmsghdr), (void *)mmsghdr_pointer + i) != 0)
		{
			continue;
		}

		struct auxiliary_map* auxmap = auxmap__get();
		if(!auxmap)
		{
			continue;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMSG_E);

		/*=============================== COLLECT PARAMETERS  ===========================*/

		/* Parameter 1: fd (type: PT_FD) */
		int32_t socket_fd = (int32_t)args[0];
		auxmap__store_s64_param(auxmap, (int64_t)socket_fd);

		/* Parameter 2: size (type: PT_UINT32) */
		unsigned long msghdr_pointer = (unsigned long)&mmsghdr.msg_hdr;
		auxmap__store_msghdr_size_param(auxmap, msghdr_pointer);

		/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
		/* TODO: Here we don't know if this fd is a socket or not,
		 * since we are in the enter event and the syscall could fail.
		 * This shouldn't be a problem since if it is not a socket fd
		 * the `bpf_probe_read()` call we fail. Probably we have to move it
		 * in the exit event.
		 */
		if(socket_fd >= 0)
		{
			/*
			struct sockaddr *usrsockaddr;
			struct msghdr *msg = (struct msghdr*)msghdr_pointer;
			BPF_CORE_READ_USER_INTO(&usrsockaddr, msg, msg_name);
			*/
			auxmap__store_socktuple_param(auxmap, socket_fd, OUTBOUND, mmsghdr.msg_hdr.msg_name);
		}
		else
		{
			auxmap__store_empty_param(auxmap);
		}

		/*=============================== COLLECT PARAMETERS  ===========================*/

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap, ctx);
	}

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(sendmmsg_x,
	     struct pt_regs *regs,
	     long ret)
{
	if (ret < 0)
	{
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[2];
	extract__network_args(args, 2, regs);

	struct mmsghdr mmsghdr;
	struct mmsghdr *mmsghdr_pointer = (struct mmsghdr *)args[1];

	for (int i = 0; i < ret && i < 16; i++)
	{
		if (bpf_probe_read_user((void *)&mmsghdr, bpf_core_type_size(struct mmsghdr), (void *)mmsghdr_pointer + i) != 0)
		{
			continue;
		}

		struct auxiliary_map* auxmap = auxmap__get();
		if(!auxmap)
		{
			continue;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMSG_X);

		/*=============================== COLLECT PARAMETERS  ===========================*/

		/* Parameter 1: res (type: PT_ERRNO) */
		auxmap__store_s64_param(auxmap, mmsghdr.msg_len);

		/* In case of failure `bytes_to_read` could be also lower than `snaplen`
		 * but we will discover it directly into `auxmap__store_iovec_data_param`
		 * otherwise we need to extract it now and it has a cost. Here we check just
		 * the return value if the syscall is successful.
		 */
		uint16_t snaplen = maps__get_snaplen();
		apply_dynamic_snaplen(regs, &snaplen, true);
		if(mmsghdr.msg_len > 0 && snaplen > mmsghdr.msg_len)
		{
			snaplen = mmsghdr.msg_len;
		}

		/* Parameter 2: data (type: PT_BYTEBUF) */
		unsigned long msghdr_pointer = (unsigned long)&mmsghdr.msg_hdr;
		auxmap__store_msghdr_data_param(auxmap, msghdr_pointer, snaplen);

		/*=============================== COLLECT PARAMETERS  ===========================*/

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap, ctx);
	}

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
