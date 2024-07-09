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
int BPF_PROG(recvmmsg_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[1];
	extract__network_args(args, 1, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, RECVMSG_E_SIZE, PPME_SOCKET_RECVMSG_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD)*/
	int32_t fd = (int32_t)args[0];
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(recvmmsg_x,
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

		auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMSG_X);

		/*=============================== COLLECT PARAMETERS  ===========================*/

		/* Parameter 1: res (type: PT_ERRNO) */
		auxmap__store_s64_param(auxmap, mmsghdr.msg_len);

		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, (uint32_t)mmsghdr.msg_len);

		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		uint16_t snaplen = maps__get_snaplen();
		apply_dynamic_snaplen(regs, &snaplen, true);
		if(snaplen > mmsghdr.msg_len)
		{
			snaplen = mmsghdr.msg_len;
		}

		/* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_msghdr_data_param(auxmap, (unsigned long)&mmsghdr.msg_hdr, snaplen);

		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		uint32_t socket_fd = (uint32_t)args[0];
		auxmap__store_socktuple_param(auxmap, socket_fd, INBOUND, (struct sockaddr*)mmsghdr.msg_hdr.msg_name);

		/* Parameter 5: msg_control (type: PT_BYTEBUF) */
		if (mmsghdr.msg_hdr.msg_control != NULL)
		{
			auxmap__store_bytebuf_param(auxmap, (unsigned long)mmsghdr.msg_hdr.msg_control, mmsghdr.msg_hdr.msg_controllen, USER);
		} else {
			auxmap__store_empty_param(auxmap);
		}

		/*=============================== COLLECT PARAMETERS  ===========================*/

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap, ctx);
	}

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
