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
int BPF_PROG(sendmmsg_e, struct pt_regs *regs, long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SENDMMSG_E_SIZE, PPME_SOCKET_SENDMMSG_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameter to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

__always_inline static int handle_hotplug() {
	/* We assume that the ring buffer for CPU 0 is always there so we send the
	 * HOT-PLUG event through this buffer.
	 */
	uint32_t cpu_0 = 0;
	struct ringbuf_map *rb = bpf_map_lookup_elem(&ringbuf_maps, &cpu_0);
	if(!rb)
	{
		bpf_printk("unable to obtain the ring buffer for CPU 0");
		return 0;
	}

	struct counter_map *counter = bpf_map_lookup_elem(&counter_maps, &cpu_0);
	if(!counter)
	{
		bpf_printk("unable to obtain the counter map for CPU 0");
		return 0;
	}

	/* This counts the event seen by the drivers even if they are dropped because the buffer is full. */
	counter->n_evts++;

	/* If we are not able to reserve space we stop here
	 * the event collection.
	 */
	struct ringbuf_struct ringbuf;
	ringbuf.reserved_event_size = HOTPLUG_E_SIZE;
	ringbuf.event_type = PPME_CPU_HOTPLUG_E;
	ringbuf.data = bpf_ringbuf_reserve(rb, HOTPLUG_E_SIZE, 0);
	if(!ringbuf.data)
	{
		counter->n_drops_buffer++;
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	/* Parameter 1: cpu (type: PT_UINT32) */
	uint32_t current_cpu_id = (uint32_t)bpf_get_smp_processor_id();
	ringbuf__store_u32(&ringbuf, current_cpu_id);

	/* Parameter 2: action (type: PT_UINT32) */
	/* Right now we don't have actions we always send 0 */
	ringbuf__store_u32(&ringbuf, 0);

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);
	return 0;
}

typedef struct sendmmsg_exit_s
{
	uint32_t fd;
	struct mmsghdr *mmh;
	struct pt_regs *regs;
	void *ctx;
} sendmmsg_exit_t;

__always_inline static long handle_exit(uint32_t index, void *ctx)
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

	/* Parameter 2: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, (int64_t)data->fd);

	/* Parameter 3: size (type: PT_UINT32) */
	auxmap__store_iovec_size_param(auxmap, (unsigned long)mmh.msg_hdr.msg_iov, mmh.msg_hdr.msg_iovlen);

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

	/* Parameter 4: data (type: PT_BYTEBUF) */
	unsigned long msghdr_pointer = (unsigned long)&mmh.msg_hdr;
	auxmap__store_iovec_data_param(auxmap, (unsigned long)mmh.msg_hdr.msg_iov, mmh.msg_hdr.msg_iovlen, snaplen);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE)*/
	/* TODO: Check if the fd is a socket */
	if(data->fd >= 0)
	{
		auxmap__store_socktuple_param(auxmap, data->fd, OUTBOUND, mmh.msg_hdr.msg_name);
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
int BPF_PROG(sendmmsg_x, struct pt_regs *regs, long ret)
{
	if(ret < 0)
	{
		struct auxiliary_map *auxmap = auxmap__get();
		if(!auxmap)
		{
			return 0;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMMSG_X);

		/* Parameter 1: res (type: PT_ERRNO) */
		auxmap__store_s64_param(auxmap, ret);

		/* Parameter 2: fd (type: PT_FD) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 3: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, 0);

		/* Parameter 4: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		auxmap__store_empty_param(auxmap);

		auxmap__finalize_event_header(auxmap);

		if (auxmap__try_submit_event(auxmap) != 0)
		{
			return handle_hotplug();
		}
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[2];
	extract__network_args(args, 2, regs);
	sendmmsg_exit_t data = {
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
			return handle_hotplug();
		}
		return 0;
	}

	for(int i = 0; i < ret && i < MAX_IOVCNT; i++)
	{
		if(handle_exit(i, &data) != 0)
		{
			return handle_hotplug();
		}
	}

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
