/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

////////////////////////////////////////////////////////////////////////////
// Private definitions for the scap library
////////////////////////////////////////////////////////////////////////////

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "engine_handle.h"
#include "scap_vtable.h"
#include "ringbuffer/devset.h"
#include "engine/kmod/kmod.h"

#include "settings.h"
#include "plugin_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#if CYGWING_AGENT || _WIN32
typedef struct wh_t wh_t;
#endif

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <assert.h>
#if defined(USE_ZLIB) && !defined(UDIG)
#include <zlib.h>
#else
#define	gzFile FILE*
#define gzflush(X, Y) fflush(X)
#define gzopen fopen
#define	gzdopen(fd, mode) stdout
#define gzclose fclose
#define gzoffset ftell
#define gzwrite(F, B, S) fwrite(B, 1, S, F)
#define gzread(F, B, S) fread(B, 1, S, F)
#define gztell(F) ftell(F)
inline const char *gzerror(FILE *F, int *E) {*E = ferror(F); return "error reading file descriptor";}
#define gzseek fseek
#endif

//
// Read buffer timeout constants
//
#ifdef _WIN32
#define BUFFER_EMPTY_WAIT_TIME_US_START 1000
#else
#define BUFFER_EMPTY_WAIT_TIME_US_START 500
#endif
#define BUFFER_EMPTY_WAIT_TIME_US_MAX (30 * 1000)
#define BUFFER_EMPTY_THRESHOLD_B 20000

//
// Process flags
//
#define PF_CLONING 1

typedef struct scap_tid
{
	uint64_t tid;

	UT_hash_handle hh; ///< makes this structure hashable
} scap_tid;

typedef enum ppm_reader_type
{
	RT_FILE = 0
} ppm_reader_type;

struct scap_reader
{
	ppm_reader_type m_type;
	gzFile m_file;
};

//
// The open instance handle
//
struct scap
{
	const struct scap_vtable *m_vtable;
	struct scap_engine_handle m_engine;

	scap_mode_t m_mode;
	scap_reader_t* m_reader;
	char* m_reader_evt_buf;
	size_t m_reader_evt_buf_size;

	uint32_t m_last_evt_dump_flags;
	char m_lasterr[SCAP_LASTERR_SIZE];

	// Used for scap_strerror
	char m_strerror_buf[SCAP_LASTERR_SIZE];

	scap_threadinfo* m_proclist;
	scap_mountinfo* m_dev_list;
	scap_threadinfo m_fake_kernel_proc;
	uint64_t m_evtcnt;
	scap_addrlist* m_addrlist;
	scap_machine_info m_machine_info;
	scap_userlist* m_userlist;
	proc_entry_callback m_proc_callback;
	void* m_proc_callback_context;
	struct ppm_proclist_info* m_driver_procinfo;
	bool refresh_proc_table_when_saving;
	uint32_t m_fd_lookup_limit;
	uint64_t m_unexpected_block_readsize;
	uint32_t m_ncpus;
	uint8_t m_cgroup_version;

	// Abstraction layer for windows
#if CYGWING_AGENT || _WIN32
	wh_t* m_whh;
	void* m_win_buf_handle;
	void* m_win_descs_handle;
#endif

	// The set of process names that are suppressed
	char **m_suppressed_comms;
	uint32_t m_num_suppressed_comms;

	// The active set of threads that are suppressed
	scap_tid *m_suppressed_tids;

	// The number of events that were skipped due to the comm
	// matching an entry in m_suppressed_comms.
	uint64_t m_num_suppressed_evts;

	bool syscalls_of_interest[SYSCALL_TABLE_SIZE];

	// API version supported by the driver
	// If the API version is unavailable for whatever reason,
	// it's equivalent to version 0.0.0
	uint64_t m_api_version;

	// schema version supported by the driver
	// If the schema version is unavailable for whatever reason,
	// it's equivalent to version 0.0.0
	uint64_t m_schema_version;
};

typedef enum ppm_dumper_type
{
	DT_FILE = 0,
	DT_MEM = 1,
	DT_MEMSTREAM = 2,
}ppm_dumper_type;

struct scap_dumper
{
	gzFile m_f;
	FILE* m_memstream;
	ppm_dumper_type m_type;
	uint8_t* m_targetbuf;
	uint8_t* m_targetbufcurpos;
	uint8_t* m_targetbufend;
};

struct scap_ns_socket_list
{
	int64_t net_ns;
	scap_fdinfo* sockets;
	UT_hash_handle hh;
};

//
// Misc stuff
//
#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
#define READER_BUF_SIZE (1 << 16) // UINT16_MAX + 1, ie: 65536

//
// Internal library functions
//

// Read the full event buffer for the given processor
int32_t scap_readbuf(scap_t* handle, uint32_t proc, OUT char** buf, OUT uint32_t* len);
// Read a single thread info from /proc
int32_t scap_proc_read_thread(scap_t* handle, char* procdirname, uint64_t tid, struct scap_threadinfo** pi, char *error, bool scan_sockets);
// Scan a directory containing process information
int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, char *error);
// Scan process information from engine vtable
int32_t scap_proc_scan_vtable(char *error, scap_t *handle);
// Remove an entry from the process list by parsing a PPME_PROC_EXIT event
// void scap_proc_schedule_removal(scap_t* handle, scap_evt* e);
// Remove the process that was scheduled for deletion for this handle
// void scap_proc_remove_scheduled(scap_t* handle);
// Free the process table
void scap_proc_free_table(scap_t* handle);
// Copy the fd table of a process into the one of another process
// int32_t scap_proc_copy_fd_table(scap_t* handle, scap_threadinfo* dst, scap_threadinfo* src);
// Internal helper function to output the process table to screen
void scap_proc_print_info(scap_t *handle, scap_threadinfo* pi);
void scap_proc_print_table(scap_t* handle);
// Free all the state related to a process and delete it from the fd table
void scap_proc_delete(scap_t* handle, scap_threadinfo* proc);
// Internal helper function to output the fd table of a process
void scap_fd_print_table(scap_t *handle, scap_threadinfo* pi);
// Internal helper function to output an fd table
void scap_fd_print_fd_table(scap_t *handle, scap_fdinfo* fds);
// Given an event, get the info entry for the process that generated it.
// NOTE: this is different from scap_event_getprocinfo() because it returns the full event information
// struct scap_threadinfo* scap_proc_get_from_event(scap_t* handle, scap_evt* e);
// Return the process info entry given a tid
// Free an fd table and set it to NULL when done
void scap_fd_free_table(scap_t* handle, scap_fdinfo** fds);
void scap_fd_free_ns_sockets_list(scap_t* handle, struct scap_ns_socket_list** sockets);
// Free a process' fd table
void scap_fd_free_proc_fd_table(scap_t* handle, scap_threadinfo* pi);
// Convert an fd entry's info into a string
int32_t scap_fd_info_to_string(scap_t *handle, scap_fdinfo* fdi, OUT char* str, uint32_t strlen);
// Calculate the length on disk of an fd entry's info
uint32_t scap_fd_info_len(scap_fdinfo* fdi);
// Write the given fd info to disk
int32_t scap_fd_write_to_disk(scap_t* handle, scap_fdinfo* fdi, scap_dumper_t* dumper, uint32_t len);
// Populate the given fd by reading the info from disk
uint32_t scap_fd_read_from_disk(scap_t* handle, OUT scap_fdinfo* fdi, OUT size_t* nbytes, uint32_t block_type, scap_reader_t* r);
// Parse the headers of a trace file and load the tables
int32_t scap_read_init(scap_t* handle, scap_reader_t* r);
// Add the file descriptor info pointed by fdi to the fd table for process pi.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
int32_t scap_add_fd_to_proc_table(scap_t* handle, scap_threadinfo* pi, scap_fdinfo* fdi, char *error);
// Remove the given fd from the process table of the process pointed by pi
void scap_fd_remove(scap_t* handle, scap_threadinfo* pi, int64_t fd);
// Read an event from disk
int32_t scap_next_offline(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);
// read the file descriptors for a given process directory
int32_t scap_fd_scan_fd_dir(scap_t* handle, char * procdir, scap_threadinfo* pi, struct scap_ns_socket_list** sockets_by_ns, char *error);
// scan fd information for a specific thread from engine vtable. src_tinfo is a pointer to a threadinfo returned by the engine
int32_t scap_fd_scan_vtable(scap_t *handle, const scap_threadinfo *src_tinfo, scap_threadinfo *dst_tinfo, char *error);
// read tcp or udp sockets from the proc filesystem
int32_t scap_fd_read_ipv4_sockets_from_proc_fs(scap_t* handle, const char * dir, int l4proto, scap_fdinfo ** sockets);
// read all sockets and add them to the socket table hashed by their ino
int32_t scap_fd_read_sockets(scap_t* handle, char* procdir, struct scap_ns_socket_list* sockets, char *error);
// get the device major/minor number for the requested_mount_id, looking in procdir/mountinfo if needed
uint32_t scap_get_device_by_mount_id(scap_t *handle, const char *procdir, unsigned long requested_mount_id);
// prints procs details for a give tid
void scap_proc_print_proc_by_tid(scap_t* handle, uint64_t tid);
// Allocate and return the list of interfaces on this system
int32_t scap_create_iflist(scap_t* handle);
// Free a previously allocated list of interfaces
void scap_free_iflist(scap_addrlist* ifhandle);
// Allocate and return the list of users on this system
int32_t scap_create_userlist(scap_t* handle);
// Free a previously allocated list of users
void scap_free_userlist(scap_userlist* uhandle);
// Allocate a file descriptor
int32_t scap_fd_allocate_fdinfo(scap_t *handle, scap_fdinfo **fdi, int64_t fd, scap_fd_type type);
// Free a file descriptor
void scap_fd_free_fdinfo(scap_fdinfo **fdi);

int32_t scap_fd_post_process_unix_sockets(scap_t* handle, scap_fdinfo* sockets);

int32_t scap_proc_fill_cgroups(scap_t *handle, struct scap_threadinfo* tinfo, const char* procdirname);

bool scap_alloc_proclist_info(struct ppm_proclist_info **proclist_p, uint32_t n_entries, char* error);

// Determine whether or not the provided event should be suppressed,
// based on its event type and parameters. May update the set of
// suppressed tids as a side-effect.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_check_suppressed(scap_t *handle, scap_evt *pevent,
			      bool *suppressed);

// Possibly add or remove the provided comm, tid combination to the
// set of suppressed processes. If the ptid is currently in the
// suppressed set, the tid will always be added to the suppressed
// set. Otherwise, the tid will be added if the comm matches an entry
// in suppressed_comms.
//
// Sets *suppressed to whether, after this check, the tid is suppressed.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_update_suppressed(scap_t *handle,
			       const char *comm,
			       uint64_t tid, uint64_t ptid,
			       bool *suppressed);

// Wrapper around strerror using buffer in handle
const char *scap_strerror(scap_t *handle, int errnum);
const char *scap_strerror_r(char *buf, int errnum);

int32_t scap_procfs_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr);
int32_t scap_os_getpid_global(struct scap_engine_handle engine, int64_t *pid, char* error);

//
// ASSERT implementation
//

#ifdef ASSERT
#undef ASSERT
#endif // ASSERT
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

#define CHECK_READ_SIZE(read_size, expected_size) if(read_size != expected_size) \
	{\
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "expecting %d bytes, read %d at %s, line %d. Is the file truncated?",\
			(int)expected_size,\
			(int)read_size,\
			__FILE__,\
			__LINE__);\
		return SCAP_FAILURE;\
	}

#define CHECK_READ_SIZE_WITH_FREE(alloc_buffer, read_size, expected_size) if(read_size != expected_size) \
    	{\
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "expecting %d bytes, read %d at %s, line %d. Is the file truncated?",\
			(int)expected_size,\
			(int)read_size,\
			__FILE__,\
			__LINE__);\
		free(alloc_buffer);\
		return SCAP_FAILURE;\
	}

//
// Useful stuff
//
#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#define MAX(X,Y) ((X) > (Y)? (X):(Y))
#endif


//
// Driver proc info table sizes
//
#define SCAP_DRIVER_PROCINFO_INITIAL_SIZE 7
#define SCAP_DRIVER_PROCINFO_MAX_SIZE 128000

extern const enum ppm_syscall_code g_syscall_code_routing_table[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const struct ppm_syscall_desc g_syscall_info_table[];
extern const struct ppm_event_entry g_ppm_events[];
extern bool validate_info_table_size();

extern unsigned char g_bpf_drop_syscalls[];

//
// udig stuff
//
int32_t udig_begin_capture(struct scap_engine_handle engine, char *error);
void udig_start_capture(struct scap_device *dev);
void udig_stop_capture(struct scap_device *dev);
void udig_end_capture(struct scap_engine_handle engine);
int32_t udig_set_snaplen(struct scap_engine_handle engine, uint32_t snaplen);
int32_t udig_stop_dropping_mode(struct scap_engine_handle engine);
int32_t udig_start_dropping_mode(struct scap_engine_handle engine, uint32_t sampling_ratio);

//
// scap_reader functions implementation
//

static inline scap_reader_t *scap_reader_open_gzfile(gzFile file)
{
	if (file == NULL)
	{
		return NULL;
	}
	scap_reader_t* r = (scap_reader_t *) malloc (sizeof (scap_reader_t));
	r->m_type = RT_FILE;
	r->m_file = file;
	return r;
}

static inline ppm_reader_type scap_reader_type(scap_reader_t *r)
{
	ASSERT(r != NULL);
	return r->m_type;
}

static inline int scap_reader_read(scap_reader_t *r, void* buf, uint32_t len)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzread(r->m_file, buf, len);
		default:
			ASSERT(false);
			return 0;
	}
}

static inline int64_t scap_reader_offset(scap_reader_t *r)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzoffset(r->m_file);
		default:
			ASSERT(false);
			return -1;
	}
}

static inline int64_t scap_reader_tell(scap_reader_t *r)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gztell(r->m_file);
		default:
			ASSERT(false);
			return -1;
	}
}

static inline int64_t scap_reader_seek(scap_reader_t *r, int64_t offset, int whence)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzseek(r->m_file, offset, whence);
		default:
			ASSERT(false);
			return -1;
	}
}

static inline const char *scap_reader_error(scap_reader_t *r, int *errnum)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzerror(r->m_file, errnum);
		default:
			ASSERT(false);
			*errnum = -1;
			return "unknown scap_reader type";
	}
}

static inline int scap_reader_close(scap_reader_t *r)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzclose(r->m_file);
		default:
			ASSERT(false);
			return -1;
	}
}

#ifdef __cplusplus
}
#endif
