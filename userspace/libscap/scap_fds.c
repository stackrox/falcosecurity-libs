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
#include <stdio.h>
#include <stdlib.h>

#include "scap.h"
#include "scap-int.h"
#include "uthash.h"
#include <inttypes.h>
#include <string.h>

void scap_fd_free_table(scap_fdinfo **fds)
{
	struct scap_fdinfo *fdi;
	struct scap_fdinfo *tfdi;

	if(*fds)
	{
		HASH_ITER(hh, *fds, fdi, tfdi)
		{
			HASH_DEL(*fds, fdi);
			free(fdi);
		}
		*fds = NULL;
	}
}

void scap_fd_free_proc_fd_table(scap_threadinfo *tinfo)
{
	if(tinfo->fdlist)
	{
		scap_fd_free_table(&tinfo->fdlist);
	}
}


//
// Add the file descriptor info pointed by fdi to the fd table for process tinfo.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
//
int32_t scap_add_fd_to_proc_table(struct scap_proclist *proclist, scap_threadinfo *tinfo, scap_fdinfo *fdi, char *error)
{
	int32_t uth_status = SCAP_SUCCESS;
	scap_fdinfo *tfdi;

	//
	// Make sure this fd doesn't already exist
	//
	HASH_FIND_INT64(tinfo->fdlist, &(fdi->fd), tfdi);
	if(tfdi != NULL)
	{
		//
		// This can happen if:
		//  - a close() has been dropped when capturing
		//  - an fd has been closed by clone() or execve() (it happens when the fd is opened with the FD_CLOEXEC flag,
		//    which we don't currently parse.
		// In either case, removing the old fd, replacing it with the new one and keeping going is a reasonable
		// choice.
		//
		HASH_DEL(tinfo->fdlist, tfdi);
		free(tfdi);
	}

	//
	// Add the fd to the table, or fire the notification callback
	//
	if(proclist->m_proc_callback == NULL)
	{
		HASH_ADD_INT64(tinfo->fdlist, fd, fdi);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		proclist->m_proc_callback(
			proclist->m_proc_callback_context,
			proclist->m_main_handle, tinfo->tid, tinfo, fdi);
	}

	return SCAP_SUCCESS;
}

//
// Delete a device entry
//
void scap_dev_delete(scap_t* handle, scap_mountinfo* dev)
{
	//
	// First, remove the process descriptor from the table
	//
	HASH_DEL(handle->m_dev_list, dev);

	//
	// Second, free the memory
	//
	free(dev);
}

//
// Free the device table
//
void scap_free_device_table(scap_t* handle)
{
	scap_mountinfo *dev, *tdev;

	HASH_ITER(hh, handle->m_dev_list, dev, tdev)
	{
		scap_dev_delete(handle, dev);
	}
}

int32_t scap_fd_allocate_fdinfo(scap_fdinfo **fdi, int64_t fd, scap_fd_type type)
{
	ASSERT(NULL == *fdi);
	*fdi = (scap_fdinfo *)malloc(sizeof(scap_fdinfo));
	if(*fdi == NULL)
	{
		return SCAP_FAILURE;
	}
	(*fdi)->type = type;
	(*fdi)->fd = fd;
	return SCAP_SUCCESS;
}

void scap_fd_free_fdinfo(scap_fdinfo **fdi)
{
	if(NULL != *fdi)
	{
		free(*fdi);
		*fdi = NULL;
	}
}

#if  defined(HAS_CAPTURE) && !defined(_WIN32)
char * decode_st_mode(struct stat* sb)
{
	switch(sb->st_mode & S_IFMT) {
    case S_IFBLK:
    	return "block device";
    	break;
    case S_IFCHR:
    	return "character device";
    	break;
    case S_IFDIR:
    	return "directory";
    	break;
    case S_IFIFO:
    	return "FIFO/pipe";
    	break;
    case S_IFLNK:
    	return "symlink";
    	break;
    case S_IFREG:
    	return "regular file";
    	break;
    case S_IFSOCK:
    	return "socket";
    	break;
    default:
    	return "unknown?";
    	break;
    }
}
//
// Scan the directory containing the fd's of a proc /proc/x/fd
//
int32_t scap_fd_scan_fd_dir(scap_t *handle, char *procdir, scap_threadinfo *tinfo, struct scap_ns_socket_list **sockets_by_ns, char *error)
{
	DIR *dir_p;
	struct dirent *dir_entry_p;
	int32_t res = SCAP_SUCCESS;
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char f_name[SCAP_MAX_PATH_SIZE];
	char link_name[SCAP_MAX_PATH_SIZE];
	struct stat sb;
	uint64_t fd;
	scap_fdinfo *fdi = NULL;
	uint64_t net_ns;
	ssize_t r;
	uint16_t fd_added = 0;

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%sfd", procdir);
	dir_p = opendir(fd_dir_name);
	if(dir_p == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error opening the directory %s", fd_dir_name);
		return SCAP_NOTFOUND;
	}

	//
	// Get the network namespace of the process
	//
	snprintf(f_name, sizeof(f_name), "%sns/net", procdir);
	r = readlink(f_name, link_name, sizeof(link_name));
	if(r <= 0)
	{
		//
		// No network namespace available. Assume global
		//
		net_ns = 0;
	}
	else
	{
		link_name[r] = '\0';
		sscanf(link_name, "net:[%"PRIi64"]", &net_ns);
	}

	while((dir_entry_p = readdir(dir_p)) != NULL &&
		(handle->m_fd_lookup_limit == 0 || fd_added < handle->m_fd_lookup_limit))
	{
		fdi = NULL;
		snprintf(f_name, SCAP_MAX_PATH_SIZE, "%s/%s", fd_dir_name, dir_entry_p->d_name);

		if(-1 == stat(f_name, &sb) || 1 != sscanf(dir_entry_p->d_name, "%"PRIu64, &fd))
		{
			continue;
		}

		/* Begin StackRox Section */
		// StackRox does not track non-socket fds
		if(!S_ISSOCK(sb.st_mode))
		{
			continue;
		}
		/* End StackRox Section */

		// In no driver mode to limit cpu usage we just parse sockets
		// because we are interested only on them
		if(handle->m_mode == SCAP_MODE_NODRIVER && !S_ISSOCK(sb.st_mode))
		{
			continue;
		}

		switch(sb.st_mode & S_IFMT)
		{
		case S_IFIFO:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_FIFO);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for fifo fd %" PRIu64, fd);
				break;
			}
			res = scap_fd_handle_pipe(handle, f_name, tinfo, fdi, error);
			break;
		case S_IFREG:
		case S_IFBLK:
		case S_IFCHR:
		case S_IFLNK:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_FILE_V2);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for file fd %" PRIu64, fd);
				break;
			}
			fdi->ino = sb.st_ino;
			res = scap_fd_handle_regular_file(handle, f_name, tinfo, fdi, procdir, error);
			break;
		case S_IFDIR:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_DIRECTORY);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for dir fd %" PRIu64, fd);
				break;
			}
			fdi->ino = sb.st_ino;
			res = scap_fd_handle_regular_file(handle, f_name, tinfo, fdi, procdir, error);
			break;
		case S_IFSOCK:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_UNKNOWN);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for sock fd %" PRIu64, fd);
				break;
			}
			res = scap_fd_handle_socket(handle, f_name, tinfo, fdi, procdir, net_ns, sockets_by_ns, error);
			if(handle->m_proc_callback == NULL)
			{
				// we can land here if we've got a netlink socket
				if(fdi->type == SCAP_FD_UNKNOWN)
				{
					scap_fd_free_fdinfo(&fdi);
				}
			}
			break;
		default:
			res = scap_fd_allocate_fdinfo(handle, &fdi, fd, SCAP_FD_UNSUPPORTED);
			if(SCAP_FAILURE == res)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for unsupported fd %" PRIu64, fd);
				break;
			}
			fdi->ino = sb.st_ino;
			res = scap_fd_handle_regular_file(handle, f_name, tinfo, fdi, procdir, error);
			break;
		}

		if(handle->m_proc_callback != NULL)
		{
			if(fdi)
			{
				scap_fd_free_fdinfo(&fdi);
			}
		}

		if(SCAP_SUCCESS != res)
		{
			break;
		} else {
			++fd_added;
		}
	}
	closedir(dir_p);
	return res;
}


#endif // HAS_CAPTURE

//
// Internal helper function to output the fd table of a process
//
void scap_fd_print_table(scap_t *handle, scap_threadinfo *tinfo)
{
	scap_fd_print_fd_table(handle, tinfo->fdlist);
}

void scap_fd_print_fd_table(scap_t *handle, scap_fdinfo *fds)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;
	char str[SCAP_MAX_PATH_SIZE];

	HASH_ITER(hh, fds, fdi, tfdi)
	{
		if(scap_fd_info_to_string(handle, fdi, str, SCAP_MAX_PATH_SIZE) != SCAP_SUCCESS)
		{
			ASSERT(false);
			snprintf(str, SCAP_MAX_PATH_SIZE, "N.A.");
		}
		fprintf(stderr, "  %"PRIu64") %s\n", fdi->fd, str);
	}
}

