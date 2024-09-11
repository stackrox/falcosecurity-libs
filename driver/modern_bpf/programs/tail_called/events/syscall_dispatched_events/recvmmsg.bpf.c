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
	unsigned long socket_fd = 0;
	extract__network_args(&socket_fd, 1, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, RECVMMSG_E_SIZE, PPME_SOCKET_RECVMMSG_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, (int64_t)(int32_t)socket_fd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

typedef struct recvmmsg_data_s
{
	uint32_t fd;
	struct mmsghdr *mmh;
	struct pt_regs *regs;
	void* ctx;
} recvmmsg_data_t;

static long handle_exit(uint32_t index, void *ctx)
{
	recvmmsg_data_t *data = (recvmmsg_data_t *)ctx;
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

	auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, mmh.msg_len);

	/* Parameter 2: size (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, (uint32_t)mmh.msg_len);

	/* We read the minimum between `snaplen` and what we really
	 * have in the buffer.
	 */
	uint16_t snaplen = maps__get_snaplen();
	apply_dynamic_snaplen(data->regs, &snaplen, true, NULL);
	if(snaplen > mmh.msg_len)
	{
		snaplen = mmh.msg_len;
	}

	/* Parameter 3: data (type: PT_BYTEBUF) */
	auxmap__store_iovec_data_param(auxmap, (unsigned long)mmh.msg_hdr.msg_iov, mmh.msg_hdr.msg_iovlen, snaplen);

	/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
	auxmap__store_socktuple_param(auxmap, data->fd, INBOUND, (struct sockaddr *)mmh.msg_hdr.msg_name);

	/* Parameter 5: msg_control (type: PT_BYTEBUF) */
	if(mmh.msg_hdr.msg_control != NULL)
	{
		auxmap__store_bytebuf_param(auxmap, (unsigned long)mmh.msg_hdr.msg_control, mmh.msg_hdr.msg_controllen,
					    USER);
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct ringbuf_map *rb = maps__get_ringbuf_map();
	if(!rb)
	{
		return 1;
	}

	auxmap__finalize_event_header(auxmap);

	return auxmap__try_submit_event(auxmap);
}

SEC("tp_btf/sys_exit")
int BPF_PROG(recvmmsg_x, struct pt_regs *regs, long ret)
{
	if(ret < 0)
	{
		struct auxiliary_map *auxmap = auxmap__get();
		if(!auxmap)
		{
			return 0;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMMSG_X);

		/* Parameter 1: res (type: PT_ERRNO) */
		auxmap__store_s64_param(auxmap, ret);

		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, 0);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 5: msg_control (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap, ctx);
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[2];
	extract__network_args(args, 2, regs);
	recvmmsg_data_t data = {
		.fd = args[0],
		.mmh = (struct mmsghdr *)args[1],
		.regs = regs,
		.ctx = ctx,
	};

	// TODO: Update vmlinux.h so we can test against BPF_FUNC_loop
	if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_loop))
	{
		uint32_t nr_loops = ret < 1024 ? ret : 1024;
		long total_loops = bpf_loop(nr_loops, handle_exit, &data, 0);
		if (total_loops != nr_loops)
		{
			bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_HOTPLUG_E);
			bpf_printk("failed to tail call into the 'hotplug' prog");
		}
		return 0;
	}

	for(int i = 0; i < ret && i < 12; i++)
	{
		handle_exit(i, &data);
	}

	return 0;
}


/*=============================== EXIT EVENT ===========================*/
