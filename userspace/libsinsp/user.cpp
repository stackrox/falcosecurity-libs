/*
Copyright (C) 2022 The Falco Authors.

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

#include "user.h"
#include "event.h"
#include "utils.h"
#include "logger.h"
#include "sinsp.h"
#include "../common/strlcpy.h"

sinsp_usergroup_manager::sinsp_usergroup_manager(sinsp *inspector) : m_last_flush_time_ns(0)
{
	m_inspector = inspector;
}

void sinsp_usergroup_manager::import_host_users_groups_list()
{
	auto &host_userlist = m_userlist[""];
	auto &host_grplist = m_grouplist[""];

	uint32_t j;
	scap_userlist* ul = scap_get_user_list(m_inspector->m_h);
	if(ul)
	{
		// Store a copy to make a diff
		auto old_host_userlist = m_userlist[""];
		auto old_host_grplist = m_grouplist[""];

		// Only clean old tables if new one is actually recved
		host_userlist.clear();
		host_grplist.clear();

		for(j = 0; j < ul->nusers; j++)
		{
			host_userlist.emplace(ul->users[j].uid, ul->users[j]);
		}

		for(j = 0; j < ul->ngroups; j++)
		{
			host_grplist.emplace(ul->groups[j].gid, ul->groups[j]);
		}

		notify_host_diff(old_host_userlist, old_host_grplist);
	}
}

void sinsp_usergroup_manager::refresh_host_users_groups_list()
{
	// Avoid re-running refresh_host_users_groups_list too soon
	m_last_flush_time_ns = m_inspector->m_lastevent_ts;

	scap_refresh_userlist(m_inspector->m_h);
	import_host_users_groups_list();
}

void sinsp_usergroup_manager::delete_container_users_groups(const sinsp_container_info &cinfo)
{
	auto usrlist = get_userlist(cinfo.m_id);
	if (usrlist)
	{
		for (auto &u : *usrlist)
		{
			// We do not have a thread id here, as a removed container
			// means that it has no tIDs anymore.
			notify_user_changed(&u.second, cinfo.m_id, false);
		}
	}

	auto grplist = get_grouplist(cinfo.m_id);
	if (grplist)
	{
		for (auto &g : *grplist)
		{
			// We do not have a thread id here, as a removed container
			// means that it has no tIDs anymore.
			notify_group_changed(&g.second, cinfo.m_id, false);
		}
	}

	m_userlist.erase(cinfo.m_id);
	m_grouplist.erase(cinfo.m_id);
}

bool sinsp_usergroup_manager::sync_host_users_groups()
{
	bool res = false;

	if(m_last_flush_time_ns == 0)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts - m_inspector->m_deleted_users_groups_scan_time_ns + 60 * ONE_SECOND_IN_NS;
	}

	if(m_inspector->m_lastevent_ts >
	   m_last_flush_time_ns + m_inspector->m_deleted_users_groups_scan_time_ns)
	{
		res = true;

		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		// Store current HOST lists
		auto old_host_userlist = m_userlist.at("");
		auto old_host_grplist = m_grouplist.at("");

		// Refresh
		refresh_host_users_groups_list();
	}
	return res;
}

void sinsp_usergroup_manager::notify_host_diff(const unordered_map<uint32_t, scap_userinfo> &old_host_userlist,
					       const unordered_map<uint32_t, scap_groupinfo> &old_host_grplist)
{
	auto &host_userlist = m_userlist[""];
	auto &host_grplist = m_grouplist[""];

	// Find any user/group added
	for (auto &u : host_userlist) {
		if (old_host_userlist.find(u.first) == old_host_userlist.end()) {
			notify_user_changed(&u.second, "");
		}
	}
	for (auto &g : host_grplist) {
		if (old_host_grplist.find(g.first) == old_host_grplist.end()) {
			notify_group_changed(&g.second, "");
		}
	}

	// Find any user/group deleted
	for (auto &u : old_host_userlist) {
		if (host_userlist.find(u.first) == host_userlist.end()) {
			notify_user_changed(&u.second, "", false);
		}
	}
	for (auto &g : old_host_grplist) {
		if (host_grplist.find(g.first) == host_grplist.end()) {
			notify_group_changed(&g.second, "", false);
		}
	}
}

bool sinsp_usergroup_manager::add_user(const string &container_id, uint32_t uid, uint32_t gid, const char *name, const char *home, const char *shell)
{
	bool res = false;
	scap_userinfo *usr = get_user(container_id, uid);
	if (!usr) {
		auto &userlist = m_userlist[container_id];
		userlist[uid].uid = uid;
		userlist[uid].gid = gid;
		strlcpy(userlist[uid].name, name, MAX_CREDENTIALS_STR_LEN);
		strlcpy(userlist[uid].homedir, home, SCAP_MAX_PATH_SIZE);
		strlcpy(userlist[uid].shell, shell, SCAP_MAX_PATH_SIZE);

		res = true;
	}
	return res;
}

bool sinsp_usergroup_manager::rm_user(const string &container_id, uint32_t uid)
{
	bool res = false;
	scap_userinfo *usr = get_user(container_id, uid);
	if (usr) {
		m_userlist[container_id].erase(uid);
		res = true;
	}
	return res;
}

bool sinsp_usergroup_manager::add_group(const string &container_id, uint32_t gid, const char *name)
{
	bool res = false;
	scap_groupinfo *gr = get_group(container_id, gid);
	if (!gr) {
		auto &grplist = m_grouplist[container_id];
		grplist[gid].gid = gid;
		strlcpy(grplist[gid].name, name, MAX_CREDENTIALS_STR_LEN);

		res = true;
	}
	return res;
}

bool sinsp_usergroup_manager::rm_group(const string &container_id, uint32_t gid)
{
	bool res = false;
	scap_groupinfo *gr = get_group(container_id, gid);
	if (gr) {
		m_grouplist[container_id].erase(gid);
		res = true;
	}
	return res;
}

const unordered_map<uint32_t, scap_userinfo>* sinsp_usergroup_manager::get_userlist(const string &container_id)
{
	if (m_userlist.find(container_id) == m_userlist.end())
	{
		return nullptr;
	}
	return &m_userlist[container_id];
}

scap_userinfo* sinsp_usergroup_manager::get_user(const string &container_id, uint32_t uid)
{
	if(uid == 0xffffffff)
	{
		return nullptr;
	}

	if (m_userlist.find(container_id) == m_userlist.end())
	{
		return nullptr;
	}

	auto &userlist = m_userlist[container_id];
	auto it = userlist.find(uid);
	if(it == userlist.end())
	{
		return nullptr;
	}
	return &it->second;
}

const unordered_map<uint32_t, scap_groupinfo>* sinsp_usergroup_manager::get_grouplist(const string &container_id)
{
	if (m_grouplist.find(container_id) == m_grouplist.end())
	{
		return nullptr;
	}
	return &m_grouplist[container_id];
}

scap_groupinfo* sinsp_usergroup_manager::get_group(const std::string &container_id, uint32_t gid)
{
	if(gid == 0xffffffff)
	{
		return nullptr;
	}

	if (m_grouplist.find(container_id) == m_grouplist.end())
	{
		return nullptr;
	}

	auto &grplist = m_grouplist[container_id];
	auto it = grplist.find(gid);
	if(it == grplist.end())
	{
		return nullptr;
	}
	return &it->second;
}

bool sinsp_usergroup_manager::user_to_sinsp_event(const scap_userinfo *user, sinsp_evt* evt, const string &container_id, uint16_t ev_type)
{
	// 6 lens, uid, gid, name, home, shell, container_id
	size_t totlen = sizeof(scap_evt) + 6 * sizeof(uint16_t) +
			sizeof(uint32_t) + sizeof(uint32_t) +
			strlen(user->name) + 1 +
			strlen(user->homedir) + 1 +
			strlen(user->shell) + 1 +
			container_id.length() + 1;

	ASSERT(evt->m_pevt_storage == nullptr);
	evt->m_pevt_storage = new char[totlen];
	evt->m_pevt = (scap_evt *) evt->m_pevt_storage;

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;
	evt->m_inspector = m_inspector;

	scap_evt* scapevt = evt->m_pevt;

	if(m_inspector->m_lastevent_ts == 0)
	{
		// This can happen at startup when containers are
		// being created as a part of the initial process
		// scan.
		scapevt->ts = sinsp_utils::get_current_time_ns();
	}
	else
	{
		scapevt->ts = m_inspector->m_lastevent_ts;
	}
	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = ev_type;
	scapevt->nparams = 6;

	auto* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + scapevt->nparams * sizeof(uint16_t);

	lens[0] = sizeof(uint32_t);
	lens[1] = sizeof(uint32_t);
	lens[2] = strlen(user->name) + 1;
	lens[3] = strlen(user->homedir) + 1;
	lens[4] = strlen(user->shell) + 1;
	lens[5] = container_id.length() + 1;

	memcpy(valptr, &user->uid, lens[0]);
	valptr += lens[0];
	memcpy(valptr, &user->gid, lens[1]);
	valptr += lens[1];
	memcpy(valptr, user->name, lens[2]);
	valptr += lens[2];
	memcpy(valptr, user->homedir, lens[3]);
	valptr += lens[3];
	memcpy(valptr, user->shell, lens[4]);
	valptr += lens[4];
	memcpy(valptr, container_id.c_str(), lens[5]);

	evt->init();
	return true;
}

bool sinsp_usergroup_manager::group_to_sinsp_event(const scap_groupinfo *group, sinsp_evt* evt, const string &container_id, uint16_t ev_type)
{
	// gid, name, container_id
	size_t totlen = sizeof(scap_evt) + 3 * sizeof(uint16_t) +
			sizeof(uint32_t) +
			strlen(group->name) + 1 +
			container_id.length() + 1;

	ASSERT(evt->m_pevt_storage == nullptr);
	evt->m_pevt_storage = new char[totlen];
	evt->m_pevt = (scap_evt *) evt->m_pevt_storage;

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;
	evt->m_inspector = m_inspector;

	scap_evt* scapevt = evt->m_pevt;

	if(m_inspector->m_lastevent_ts == 0)
	{
		// This can happen at startup when containers are
		// being created as a part of the initial process
		// scan.
		scapevt->ts = sinsp_utils::get_current_time_ns();
	}
	else
	{
		scapevt->ts = m_inspector->m_lastevent_ts;
	}
	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = ev_type;
	scapevt->nparams = 3;

	auto* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + scapevt->nparams * sizeof(uint16_t);

	lens[0] = sizeof(uint32_t);
	lens[1] = strlen(group->name) + 1;
	lens[2] = container_id.length() + 1;

	memcpy(valptr, &group->gid, lens[0]);
	valptr += lens[0];
	memcpy(valptr, group->name, lens[1]);
	valptr += lens[1];
	memcpy(valptr, container_id.c_str(), lens[2]);

	evt->init();
	return true;
}

void sinsp_usergroup_manager::notify_user_changed(const scap_userinfo *user, const string &container_id, bool added)
{
	auto *evt = new sinsp_evt();

	if (added)
	{
		user_to_sinsp_event(user, evt, container_id, PPME_USER_ADDED_E);
	} else
	{
		user_to_sinsp_event(user, evt, container_id, PPME_USER_DELETED_E);
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"notify_user_changed (%d): USER event, queuing to inspector",
			user->uid);

	std::shared_ptr<sinsp_evt> cevt(evt);

#ifndef _WIN32
	m_inspector->m_pending_state_evts.push(cevt);
#endif
}

void sinsp_usergroup_manager::notify_group_changed(const scap_groupinfo *group, const string &container_id, bool added)
{
	auto *evt = new sinsp_evt();
	if (added)
	{
		group_to_sinsp_event(group, evt, container_id, PPME_GROUP_ADDED_E);
	} else
	{
		group_to_sinsp_event(group, evt, container_id, PPME_GROUP_DELETED_E);
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"notify_group_changed (%d): GROUP event, queuing to inspector",
			group->gid);

	std::shared_ptr<sinsp_evt> cevt(evt);

#ifndef _WIN32
	m_inspector->m_pending_state_evts.push(cevt);
#endif
}