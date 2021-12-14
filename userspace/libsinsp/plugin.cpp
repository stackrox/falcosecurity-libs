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

#ifndef _WIN32
#include <dlfcn.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <vector>
#include <set>
#include <sstream>
#include <numeric>
#include <json/json.h>
#include <valijson/adapters/jsoncpp_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

#include "sinsp_int.h"
#include "sinsp_exception.h"
#include "plugin.h"
#include "plugin_filtercheck.h"
#include "strlcpy.h"

using namespace std;

// Used below--set a std::string from the provided allocated charbuf
static std::string str_from_alloc_charbuf(const char* charbuf)

///////////////////////////////////////////////////////////////////////////////
// source_plugin filter check implementation
// This class implements a dynamic filter check that acts as a bridge to the
// plugin simplified field extraction implementations
///////////////////////////////////////////////////////////////////////////////

const filtercheck_field_info sinsp_filter_check_plugininfo_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.pluginname", "if the event comes from a plugin, the name of the plugin that generated it."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.plugininfo", "if the event comes from a plugin, a summary of the event as formatted by the plugin."},
};

static std::set<uint16_t> s_all_plugin_event_types = {PPME_PLUGINEVENT_E};

class sinsp_filter_check_plugininfo : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_PLUGINNAME = 0,
		TYPE_PLUGININFO = 1,
	};

	sinsp_filter_check_plugininfo()
	{
		m_info.m_name = "plugininfo";
		m_info.m_fields = sinsp_filter_check_plugininfo_fields;
		m_info.m_nfields = sizeof(sinsp_filter_check_plugininfo_fields) / sizeof(sinsp_filter_check_plugininfo_fields[0]);
		m_info.m_flags = filter_check_info::FL_NONE;
	}

	sinsp_filter_check_plugininfo(std::shared_ptr<sinsp_plugin> plugin)
		: m_plugin(plugin)
	{
		m_info.m_name = plugin->name() + string(" (plugininfo)");
		m_info.m_fields = sinsp_filter_check_plugininfo_fields;
		m_info.m_nfields = sizeof(sinsp_filter_check_plugininfo_fields) / sizeof(sinsp_filter_check_plugininfo_fields[0]);
		m_info.m_flags = filter_check_info::FL_NONE;
	}

	sinsp_filter_check_plugininfo(const sinsp_filter_check_plugininfo &p)
	{
		m_plugin = p.m_plugin;
		m_info = p.m_info;
	}

	virtual ~sinsp_filter_check_plugininfo()
	{
	}

	sinsp_filter_check* allocate_new()
	{
		return new sinsp_filter_check_plugininfo(*this);
	}

	const std::set<uint16_t> &evttypes()
	{
		return s_all_plugin_event_types;
	}

	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
	{
		//
		// Only extract if the event is a plugin event and if
		// this plugin is a source plugin.
		//
		if(!(evt->get_type() == PPME_PLUGINEVENT_E &&
		     m_plugin->type() == TYPE_SOURCE_PLUGIN))
		{
			return NULL;
		}

		//
		// Only extract if the event plugin id matches this plugin's id.
		//
		sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(m_plugin.get());

		sinsp_evt_param *parinfo;
		parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(int32_t));
		uint32_t pgid = *(int32_t *)parinfo->m_val;
		if(pgid != splugin->id())
		{
			return NULL;
		}

		switch(m_field_id)
		{
		case TYPE_PLUGINNAME:
			m_strstorage = splugin->name();
			*len = m_strstorage.size();
			return (uint8_t*) m_strstorage.c_str();
			break;
		case TYPE_PLUGININFO:
			parinfo = evt->get_param(1);
			m_strstorage = splugin->event_to_string((const uint8_t *) parinfo->m_val, parinfo->m_len);
			*len = m_strstorage.size();
			return (uint8_t*) m_strstorage.c_str();
		default:
			return NULL;
		}

		return NULL;
	}

	std::string m_strstorage;

	std::shared_ptr<sinsp_plugin> m_plugin;
};

class sinsp_filter_check_plugin : public sinsp_filter_check
{
public:
	sinsp_filter_check_plugin()
	{
		m_info.m_name = "plugin";
		m_info.m_fields = NULL;
		m_info.m_nfields = 0;
		m_info.m_flags = filter_check_info::FL_NONE;
		m_cnt = 0;
	}

	sinsp_filter_check_plugin(std::shared_ptr<sinsp_plugin> plugin)
		: m_plugin(plugin)
	{
		m_info.m_name = plugin->name() + string(" (plugin)");
		m_info.m_fields = plugin->fields();
		m_info.m_nfields = plugin->nfields();
		m_info.m_flags = filter_check_info::FL_NONE;
		m_cnt = 0;
	}

	sinsp_filter_check_plugin(const sinsp_filter_check_plugin &p)
	{
		m_plugin = p.m_plugin;
		m_info = p.m_info;
	}

	virtual ~sinsp_filter_check_plugin()
	{
	}

	const std::set<uint16_t> &evttypes()
	{
		return s_all_plugin_event_types;
	}

	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
	{
		int32_t res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);

		if(res != -1)
		{
			// Read from str to the end-of-string, or first space
			string val(str);
			size_t val_end = val.find_first_of(' ', 0);
			if(val_end != string::npos)
			{
				val = val.substr(0, val_end);
			}

			size_t pos1 = val.find_first_of('[', 0);
			if(pos1 != string::npos)
			{
				size_t argstart = pos1 + 1;
				if(argstart < val.size())
				{
					m_argstr = val.substr(argstart);
					size_t pos2 = m_argstr.find_first_of(']', 0);
					m_argstr = m_argstr.substr(0, pos2);
					m_arg = (char*)m_argstr.c_str();
					return pos1 + pos2 + 2;
				}
			}
		}

		return res;
	}

	sinsp_filter_check* allocate_new()
	{
		return new sinsp_filter_check_plugin(*this);
	}

	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
	{
		//
		// Reject any event that is not generated by a plugin
		//
		if(evt->get_type() != PPME_PLUGINEVENT_E)
		{
			return NULL;
		}

		//
		// If this is a source plugin, reject events that have
		// not been generated by a plugin with this id specifically.
		//
		// XXX/mstemm this should probably check the version as well.
		//
		sinsp_evt_param *parinfo;
		if(m_plugin->type() == TYPE_SOURCE_PLUGIN)
		{
			sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(m_plugin.get());
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int32_t));
			uint32_t pgid = *(int32_t *)parinfo->m_val;
			if(pgid != splugin->id())
			{
				return NULL;
			}
		}

		//
		// If this is an extractor plugin, only attempt to
		// extract if the source is compatible with the event
		// source.
		//
		if(m_plugin->type() == TYPE_EXTRACTOR_PLUGIN)
		{
			sinsp_extractor_plugin *eplugin = static_cast<sinsp_extractor_plugin *>(m_plugin.get());
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int32_t));
			uint32_t pgid = *(int32_t *)parinfo->m_val;

			std::shared_ptr<sinsp_plugin> plugin = m_inspector->get_plugin_by_id(pgid);

			if(!plugin)
			{
				return NULL;
			}

			sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(plugin.get());

			if(!eplugin->source_compatible(splugin->event_source()))
			{
				return NULL;
			}
		}

		//
		// Get the event payload
		//
		parinfo = evt->get_param(1);
		*len = 0;

		ppm_param_type type = m_info.m_fields[m_field_id].m_type;

		ss_plugin_event pevt;
		pevt.evtnum = evt->get_num();
		pevt.data = (uint8_t *) parinfo->m_val;
		pevt.datalen = parinfo->m_len;
		pevt.ts = evt->get_ts();

		sinsp_plugin::ext_field field;
		field.field_id = m_field_id;
		field.field = m_info.m_fields[m_field_id].m_name;
		if(m_arg != NULL)
		{
			field.arg = m_arg;
		}
		field.ftype = type;

		if (!m_plugin->extract_field(pevt, field) ||
		    ! field.field_present)
		{
			return NULL;
		}

		switch(type)
		{
		case PT_CHARBUF:
		{
			m_strstorage = field.res_str;
			*len = m_strstorage.size();
			return (uint8_t*) m_strstorage.c_str();
		}
		case PT_UINT64:
		{
			m_u64_res = field.res_u64;
			return (uint8_t *)&m_u64_res;
		}
		default:
			ASSERT(false);
			throw sinsp_exception("plugin extract error: unsupported field type " + to_string(type));
			break;
		}

		return NULL;
	}

	// XXX/mstemm m_cnt unused so far.
	uint64_t m_cnt;
	string m_argstr;
	char* m_arg = NULL;

	std::string m_strstorage;
	uint64_t m_u64_res;

	std::shared_ptr<sinsp_plugin> m_plugin;
};

///////////////////////////////////////////////////////////////////////////////
// sinsp_plugin implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_plugin::version::version()
	: m_valid(false)
{
}

sinsp_plugin::version::version(const std::string &version_str)
	: m_valid(false)
{
	m_valid = (sscanf(version_str.c_str(), "%" PRIu32 ".%" PRIu32 ".%" PRIu32,
			  &m_version_major, &m_version_minor, &m_version_patch) == 3);
}

sinsp_plugin::version::~version()
{
}

std::string sinsp_plugin::version::as_string() const
{
	return std::to_string(m_version_major) + "." +
		std::to_string(m_version_minor) + "." +
		std::to_string(m_version_patch);
}

bool sinsp_plugin::version::check(version &requested) const
{
	if(this->m_version_major != requested.m_version_major)
	{
		// major numbers disagree
		return false;
	}

	if(this->m_version_minor < requested.m_version_minor)
	{
		// framework's minor version is < requested one
		return false;
	}
	if(this->m_version_minor == requested.m_version_minor && this->m_version_patch < requested.m_version_patch)
	{
		// framework's patch level is < requested one
		return false;
	}
	return true;
}

std::shared_ptr<sinsp_plugin> sinsp_plugin::register_plugin(sinsp* inspector,
							    string filepath,
							    const char* config,
							    filter_check_list &available_checks)
{
	string errstr;
	std::shared_ptr<sinsp_plugin> plugin = create_plugin(filepath, config, errstr);

	if (!plugin)
	{
		throw sinsp_exception("cannot load plugin " + filepath + ": " + errstr.c_str());
	}

	try
	{
		inspector->add_plugin(plugin);
	}
	catch(sinsp_exception const& e)
	{
		throw sinsp_exception("cannot add plugin " + filepath + " to inspector: " + e.what());
	}

	//
	// Create and register the filter checks associated to this plugin
	//
	auto evt_filtercheck = new sinsp_filter_check_gen_event();
	available_checks.add_filter_check(evt_filtercheck);

	auto info_filtercheck = new sinsp_filter_check_plugininfo(plugin);
	available_checks.add_filter_check(info_filtercheck);

	auto filtercheck = new sinsp_filter_check_plugin(plugin);
	available_checks.add_filter_check(filtercheck);

	return plugin;
}

std::shared_ptr<sinsp_plugin> sinsp_plugin::create_plugin(string &filepath, const char* config, std::string &errstr)
{
	std::shared_ptr<sinsp_plugin> ret;

#ifdef _WIN32
	HINSTANCE handle = LoadLibrary(filepath.c_str());
#else
	void* handle = dlopen(filepath.c_str(), RTLD_LAZY);
#endif
	if(handle == NULL)
	{
		errstr = "error loading plugin " + filepath + ": " + dlerror();
		return ret;
	}

	// Before doing anything else, check the required api
	// version. If it doesn't match, return an error.

	// The pointer indirection and reference is because c++ doesn't
	// strictly allow casting void * to a function pointer. (See
	// http://www.open-std.org/jtc1/sc22/wg21/docs/cwg_defects.html#195).
	char * (*get_required_api_version)();
	*(void **) (&get_required_api_version) = getsym(handle, "plugin_get_required_api_version", errstr);
	if(get_required_api_version == NULL)
	{
		errstr = string("Could not resolve plugin_get_required_api_version function");
		return ret;
	}

	char *version_cstr = get_required_api_version();
	std::string version_str = version_cstr;
	version requestedVers(version_str);
	if(!requestedVers.m_valid)
	{
		errstr = string("Could not parse version string from ") + version_str;
		return ret;
	}
	// This is always valid
	version frameworkVers(PLUGIN_API_VERSION_STR);
	if(!frameworkVers.check(requestedVers))
	{
		errstr = string("Unsupported plugin required api version ") + version_str;
		return ret;
	}

	ss_plugin_type (*get_type)();
	*(void **) (&get_type) = getsym(handle, "plugin_get_type", errstr);
	if(get_type == NULL)
	{
		errstr = string("Could not resolve plugin_get_type function");
		return ret;
	}

	ss_plugin_type plugin_type = get_type();

	sinsp_source_plugin *splugin;
	sinsp_extractor_plugin *eplugin;

	switch(plugin_type)
	{
	case TYPE_SOURCE_PLUGIN:
		splugin = new sinsp_source_plugin();
		if(!splugin->resolve_dylib_symbols(handle, errstr))
		{
			delete splugin;
			return ret;
		}
		ret.reset(splugin);
		break;
	case TYPE_EXTRACTOR_PLUGIN:
		eplugin = new sinsp_extractor_plugin();
		if(!eplugin->resolve_dylib_symbols(handle, errstr))
		{
			delete eplugin;
			return ret;
		}
		ret.reset(eplugin);
		break;
	}

	errstr = "";

	// Initialize the plugin
	if (!ret->init(config))
	{
		errstr = string("Could not initialize plugin");
		ret = NULL;
	}

	return ret;
}

std::list<sinsp_plugin::info> sinsp_plugin::plugin_infos(sinsp* inspector)
{
	std::list<sinsp_plugin::info> ret;

	for(auto p : inspector->get_plugins())
	{
		sinsp_plugin::info info;
		info.name = p->name();
		info.description = p->description();
		info.contact = p->contact();
		info.plugin_version = p->plugin_version();
		info.required_api_version = p->required_api_version();
		info.type = p->type();

		if(info.type == TYPE_SOURCE_PLUGIN)
		{
			sinsp_source_plugin *sp = static_cast<sinsp_source_plugin *>(p.get());
			info.id = sp->id();
		}
		ret.push_back(info);
	}

	return ret;
}

sinsp_plugin::sinsp_plugin()
	: m_nfields(0)
{
}

sinsp_plugin::~sinsp_plugin()
{
}

bool sinsp_plugin::init(const char *config)
{
	if (!m_plugin_info.init)
	{
		return false;
	}

	ss_plugin_rc rc;

	ss_plugin_t *state = m_plugin_info.init(config, &rc);
	if(rc != SS_PLUGIN_SUCCESS)
	{
		// Not calling get_last_error here because there was
		// no valid ss_plugin_t struct returned from init.
		return false;
	}

	set_plugin_state(state);

	return true;
}

void sinsp_plugin::destroy()
{
	if(plugin_state() && m_plugin_info.destroy)
	{
		m_plugin_info.destroy(plugin_state());
		set_plugin_state(NULL);
	}
}

std::string sinsp_plugin::get_last_error()
{
	std::string ret;

	if(plugin_state() && m_plugin_info.get_last_error)
	{
		ret = str_from_alloc_charbuf(m_plugin_info.get_last_error(plugin_state()));
	}
	else
	{
		ret = "Plugin handle or get_last_error function not defined";
	}

	return ret;
}

const std::string &sinsp_plugin::name()
{
	return m_name;
}

const std::string &sinsp_plugin::description()
{
	return m_description;
}

const std::string &sinsp_plugin::contact()
{
	return m_contact;
}

const sinsp_plugin::version &sinsp_plugin::plugin_version()
{
	return m_plugin_version;
}

const sinsp_plugin::version &sinsp_plugin::required_api_version()
{
	return m_required_api_version;
}

const filtercheck_field_info *sinsp_plugin::fields()
{
	return m_fields.get();
}

uint32_t sinsp_plugin::nfields()
{
	return m_nfields;
}

bool sinsp_plugin::extract_field(ss_plugin_event &evt, sinsp_plugin::ext_field &field)
{
	if(!m_plugin_info.extract_fields || !plugin_state())
	{
		return false;
	}

	uint32_t num_fields = 1;
	ss_plugin_extract_field efield;
	efield.field_id = field.field_id;
	efield.field = field.field.c_str();
	efield.arg = field.arg.c_str();
	efield.ftype = field.ftype;

	ss_plugin_rc rc;

	rc = m_plugin_info.extract_fields(plugin_state(), &evt, num_fields, &efield);

	if (rc != SS_PLUGIN_SUCCESS)
	{
		return false;
	}

	field.field_present = efield.field_present;
	if (field.field_present) {
		switch(field.ftype)
		{
		case PT_CHARBUF:
			field.res_str = str_from_alloc_charbuf(efield.res_str);
			break;
		case PT_UINT64:
			field.res_u64 = efield.res_u64;
			break;
		default:
			ASSERT(false);
			throw sinsp_exception("plugin extract error: unsupported field type " + to_string(field.ftype));
			break;
		}
	}

	return true;
}

void* sinsp_plugin::getsym(void* handle, const char* name, std::string &errstr)
{
	void *ret;

#ifdef _WIN32
	ret = GetProcAddress((HINSTANCE)handle, name);
#else
	ret = dlsym(handle, name);
#endif

	if(ret == NULL)
	{
		errstr = string("Dynamic library symbol ") + name + " not present";
	} else {
		errstr = "";
	}

	return ret;
}

// Used below--set a std::string from the provided allocated charbuf and free() the charbuf.
std::string sinsp_plugin::str_from_alloc_charbuf(const char* charbuf)
{
	std::string str;

	if(charbuf != NULL)
	{
		str = charbuf;
	}

	return str;
}

std::shared_ptr<sinsp_plugin> sinsp_plugin::create(
	const std::string &filepath,
	std::string &errstr)
{
	char loadererr[PLUGIN_MAX_ERRLEN];
	auto handle = plugin_load(filepath.c_str(), loadererr);
	if (handle == NULL)
	{
		errstr = loadererr;
		return nullptr;
	}

	std::shared_ptr<sinsp_plugin> plugin(new sinsp_plugin(handle));
	if (!plugin->resolve_dylib_symbols(errstr))
	{
		// plugin and handle get deleted here by shared_ptr
		return nullptr;
	}

	return plugin;
}

plugin_caps_t sinsp_plugin::caps() const
{
	return m_caps;
}

bool sinsp_plugin::is_plugin_loaded(std::string &filepath)
{
	return plugin_is_loaded(filepath.c_str());
}

sinsp_plugin::sinsp_plugin(plugin_handle_t* handle)
	: m_state(nullptr), m_caps(CAP_NONE), m_handle(handle), m_id(-1)
{
	m_fields.clear();
}

sinsp_plugin::~sinsp_plugin()
{
	destroy();
	plugin_unload(m_handle);
	m_fields.clear();
}

bool sinsp_plugin::init(const std::string &config, std::string &errstr)
{
	if (!m_handle->api.init)
	{
		errstr = string("init api symbol not found");
		return false;
	}

	ss_plugin_rc rc;
	std::string conf = config;
	validate_init_config(conf);

	ss_plugin_t *state = m_handle->api.init(conf.c_str(), &rc);
	if (state != NULL)
	{
		// Plugins can return a state even if the result code is
		// SS_PLUGIN_FAILURE, which can be useful to set an init
		// error that can later be retrieved through get_last_error().
		m_state = state;
	}

	if (rc != SS_PLUGIN_SUCCESS)
	{
		errstr = "Could not initialize plugin: " + get_last_error();
		return false;
	}

	return true;
}

void sinsp_plugin::destroy()
{
	if(m_state && m_handle->api.destroy)
	{
		m_handle->api.destroy(m_state);
		m_state = NULL;
	}
}

std::string sinsp_plugin::get_last_error() const
{
	std::string ret;

	if(m_state)
	{
		ret = str_from_alloc_charbuf(m_handle->api.get_last_error(m_state));
	}
	else
	{
		ret = "Plugin handle or get_last_error function not defined";
	}

	return ret;
}

const std::string &sinsp_plugin::name() const
{
	return m_name;
}

const std::string &sinsp_plugin::description() const
{
	return m_description;
}

const std::string &sinsp_plugin::contact() const
{
	return m_contact;
}

const sinsp_version &sinsp_plugin::plugin_version() const
{
	return m_plugin_version;
}

const sinsp_version &sinsp_plugin::required_api_version() const
{
	return m_required_api_version;
}

void sinsp_plugin::resolve_dylib_field_arg(Json::Value root, filtercheck_field_info &tf)
{
	if (root.isNull())
	{
		return;
	}

	const Json::Value &isRequired = root.get("isRequired", Json::Value::null);
	if (!isRequired.isNull())
	{
		if (!isRequired.isBool())
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " isRequired property is not boolean");
		}

		if (isRequired.asBool() == true)
		{
			// All the extra casting is because this is the one flags value
			// that is strongly typed and not just an int.
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_REQUIRED);
		}
	}

	const Json::Value &isIndex = root.get("isIndex", Json::Value::null);
	if (!isIndex.isNull())
	{
		if (!isIndex.isBool())
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " isIndex property is not boolean");
		}

		if (isIndex.asBool() == true)
		{
			// We set `EPF_ARG_ALLOWED` implicitly.
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_INDEX);
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_ALLOWED);
		}
	}

	const Json::Value &isKey = root.get("isKey", Json::Value::null);
	if (!isKey.isNull())
	{
		if (!isKey.isBool())
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " isKey property is not boolean");
		}

		if (isKey.asBool() == true)
		{
			// We set `EPF_ARG_ALLOWED` implicitly.
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_KEY);
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_ALLOWED);
		}
	}

	if((tf.m_flags & filtercheck_field_flags::EPF_ARG_REQUIRED)
	   && !(tf.m_flags & filtercheck_field_flags::EPF_ARG_INDEX
	        || tf.m_flags & filtercheck_field_flags::EPF_ARG_KEY))
	{
		throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " arg has isRequired true, but none of isKey nor isIndex is true");
	}
	return;
}

bool sinsp_plugin::resolve_dylib_symbols(std::string &errstr)
{
	char err[PLUGIN_MAX_ERRLEN];

	// Before doing anything else, check the required api version
	if (!plugin_check_required_api_version(m_handle, err))
	{
		errstr = err;
		return false;
	}

	// check that the API requirements are satisfied
	if (!plugin_check_required_symbols(m_handle, err))
	{
		errstr = err;
		return false;
	}

	// store descriptive info in internal state
	m_name = str_from_alloc_charbuf(m_handle->api.get_name());
	m_description = str_from_alloc_charbuf(m_handle->api.get_description());
	m_contact = str_from_alloc_charbuf(m_handle->api.get_contact());
	std::string version_str = str_from_alloc_charbuf(m_handle->api.get_version());
	m_plugin_version = sinsp_version(version_str);
	if(!m_plugin_version.m_valid)
	{
		errstr = "Plugin provided an invalid version string: '" + version_str + "'";
		return false;
	}

	// read capabilities and process their info
	m_caps = plugin_get_capabilities(m_handle);

	if(m_caps & CAP_SOURCING)
	{
		m_id = m_handle->api.get_id();
		m_event_source = str_from_alloc_charbuf(m_handle->api.get_event_source());
	}

	if(m_caps & CAP_EXTRACTION)
	{
		//
		// If filter fields are exported by the plugin, get the json from get_fields(),
		// parse it, create our list of fields, and create a filtercheck from the fields.
		//
		const char *sfields = m_handle->api.get_fields();
		if (sfields == NULL) {
			throw sinsp_exception(
					string("error in plugin ") + name() + ": get_fields returned a null string");
		}
		string json(sfields);
		SINSP_DEBUG("Parsing Fields JSON=%s", json.c_str());
		Json::Value root;
		if (Json::Reader().parse(json, root) == false || root.type() != Json::arrayValue) {
			throw sinsp_exception(
					string("error in plugin ") + name() + ": get_fields returned an invalid JSON");
		}

		m_fields.clear();
		for (Json::Value::ArrayIndex j = 0; j < root.size(); j++) {
			filtercheck_field_info tf;
			tf.m_flags = EPF_NONE;

			const Json::Value &jvtype = root[j]["type"];
			string ftype = jvtype.asString();
			if (ftype == "") {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": field JSON entry has no type");
			}
			const Json::Value &jvname = root[j]["name"];
			string fname = jvname.asString();
			if (fname == "") {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": field JSON entry has no name");
			}
			const Json::Value &jvdisplay = root[j]["display"];
			string fdisplay = jvdisplay.asString();
			const Json::Value &jvdesc = root[j]["desc"];
			string fdesc = jvdesc.asString();
			if (fdesc == "") {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": field JSON entry has no desc");
			}

			strlcpy(tf.m_name, fname.c_str(), sizeof(tf.m_name));
			strlcpy(tf.m_display, fdisplay.c_str(), sizeof(tf.m_display));
			strlcpy(tf.m_description, fdesc.c_str(), sizeof(tf.m_description));
			tf.m_print_format = PF_DEC;

			if (ftype == "string") {
				tf.m_type = PT_CHARBUF;
			} else if (ftype == "uint64") {
				tf.m_type = PT_UINT64;
			} else {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": invalid field type " + ftype);
			}

			const Json::Value &jvIsList = root[j].get("isList", Json::Value::null);
			if (!jvIsList.isNull()) {
				if (!jvIsList.isBool()) {
					throw sinsp_exception(string("error in plugin ") + name() + ": field " + fname +
					                      " isList property is not boolean ");
				}

				if (jvIsList.asBool()) {
					tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
					                                        (int) filtercheck_field_flags::EPF_IS_LIST);
				}
			}

			resolve_dylib_field_arg(root[j].get("arg", Json::Value::null), tf);

			const Json::Value &jvProperties = root[j].get("properties", Json::Value::null);
			if (!jvProperties.isNull()) {
				if (!jvProperties.isArray()) {
					throw sinsp_exception(string("error in plugin ") + name() + ": field " + fname +
					                      " properties property is not array ");
				}

				for (const auto & prop : jvProperties) {
						if (!prop.isString()) {
						throw sinsp_exception(string("error in plugin ") + name() + ": field " + fname +
						                      " properties value is not string ");
					}

					const std::string &str = prop.asString();

					// "hidden" is used inside and outside libs. "info" and "conversation" are used outside libs.
					if (str == "hidden") {
						tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
						                                        (int) filtercheck_field_flags::EPF_TABLE_ONLY);
					} else if (str == "info") {
						tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
						                                        (int) filtercheck_field_flags::EPF_INFO);
					} else if (str == "conversation") {
						tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
						                                        (int) filtercheck_field_flags::EPF_CONVERSATION);
					}
				}
			}
			m_fields.push_back(tf);
		}

		if (m_handle->api.get_extract_event_sources != NULL)
		{
			std::string esources = str_from_alloc_charbuf(m_handle->api.get_extract_event_sources());

			if (esources.length() == 0)
			{
				throw sinsp_exception(string("error in plugin ") + name() +
				                      ": get_extract_event_sources returned an empty string");
			}

			Json::Value root;
			if (!Json::Reader().parse(esources, root) || root.type() != Json::arrayValue)
			{
				throw sinsp_exception(string("error in plugin ") + name() +
				                      ": get_extract_event_sources did not return a json array");
			}

			for (const auto & j : root)
			{
				if (!j.isConvertibleTo(Json::stringValue))
				{
					throw sinsp_exception(string("error in plugin ") + name() +
					                      ": get_extract_event_sources did not return a json array");
				}

				m_extract_event_sources.insert(j.asString());
			}
		}

		// A plugin with source capability
		// must extract event from its source
		if (m_caps & CAP_SOURCING)
		{
			m_extract_event_sources.insert(m_event_source);
		}
	}

	return true;
}

std::string sinsp_plugin::get_init_schema(ss_plugin_schema_type& schema_type) const
{
	schema_type = SS_PLUGIN_SCHEMA_NONE;
	if (m_handle->api.get_init_schema != NULL)
	{
		return str_from_alloc_charbuf(m_handle->api.get_init_schema(&schema_type));
	}
	return std::string("");
}

void sinsp_plugin::validate_init_config(std::string& config)
{
	ss_plugin_schema_type schema_type;
	std::string schema = get_init_schema(schema_type);
	if (!schema.empty() && schema_type != SS_PLUGIN_SCHEMA_NONE)
	{
		switch (schema_type)
		{
			case SS_PLUGIN_SCHEMA_JSON:
				validate_init_config_json_schema(config, schema);
				break;
			default:
				ASSERT(false);
				throw sinsp_exception(
					string("error in plugin ")
					+ name()
					+ ": get_init_schema returned an unknown schema type "
					+ to_string(schema_type));
		}
	}
}

void sinsp_plugin::validate_init_config_json_schema(std::string& config, std::string &schema)
{
	Json::Value schemaJson;
	if(!Json::Reader().parse(schema, schemaJson) || schemaJson.type() != Json::objectValue)
	{
		throw sinsp_exception(
			string("error in plugin ")
			+ name()
			+ ": get_init_schema did not return a json object");
	}

	// stub empty configs to an empty json object
	if (config.size() == 0)
	{
		config = "{}";
	}
	Json::Value configJson;
	if(!Json::Reader().parse(config, configJson))
	{
		throw sinsp_exception(
			string("error in plugin ")
			+ name()
			+ ": init config is not a valid json");
	}

	// validate config with json schema
	valijson::Schema schemaDef;
	valijson::SchemaParser schemaParser;
	valijson::Validator validator;
	valijson::ValidationResults validationResults;
	valijson::adapters::JsonCppAdapter configAdapter(configJson);
	valijson::adapters::JsonCppAdapter schemaAdapter(schemaJson);
	schemaParser.populateSchema(schemaAdapter, schemaDef);
	if (!validator.validate(schemaDef, configAdapter, &validationResults))
	{
		valijson::ValidationResults::Error error;
		// report only the top-most error
		if (validationResults.popError(error))
		{
			throw sinsp_exception(
				string("error in plugin ")
				+ name()
				+ " init config: In "
				+ std::accumulate(error.context.begin(), error.context.end(), std::string(""))
				+ ", "
				+ error.description);
		}
		// validation failed with no specific error
		throw sinsp_exception(
			string("error in plugin ")
			+ name()
			+ " init config: failed parsing with provided schema");
	}
}

/** Event Source CAP **/

scap_source_plugin& sinsp_plugin::as_scap_source()
{
	if (!(caps() & CAP_SOURCING))
	{
		throw sinsp_exception("Can't create scap_source_plugin from a plugin without CAP_SOURCING capability.");
	}

	m_scap_source_plugin.state = m_state;
	m_scap_source_plugin.name = m_name.c_str();
	m_scap_source_plugin.id = m_id;
	m_scap_source_plugin.open = m_handle->api.open;
	m_scap_source_plugin.close = m_handle->api.close;
	m_scap_source_plugin.get_last_error = m_handle->api.get_last_error;
	m_scap_source_plugin.next_batch = m_handle->api.next_batch;
	return m_scap_source_plugin;
}

uint32_t sinsp_plugin::id() const
{
	return m_id;
}

const std::string &sinsp_plugin::event_source() const
{
	return m_event_source;
}

std::string sinsp_plugin::get_progress(uint32_t &progress_pct) const
{
	std::string ret;
	progress_pct = 0;

	if(!m_handle->api.get_progress || !m_scap_source_plugin.handle)
	{
		return ret;
	}

	uint32_t ppct;
	ret = str_from_alloc_charbuf(m_handle->api.get_progress(m_state, m_scap_source_plugin.handle, &ppct));

	progress_pct = ppct;

	return ret;
}

std::string sinsp_plugin::event_to_string(sinsp_evt* evt) const
{
	string ret = "";
	auto datalen = evt->get_param(1)->m_len;
	auto data = (const uint8_t *) evt->get_param(1)->m_val;
	if (m_state && m_handle->api.event_to_string)
	{
		ss_plugin_event pevt;
		pevt.evtnum = evt->get_num();
		pevt.data = data;
		pevt.datalen = datalen;
		pevt.ts = evt->get_ts();
		ret = str_from_alloc_charbuf(m_handle->api.event_to_string(m_state, &pevt));
	}
	if (ret.empty())
	{
		ret += "datalen=";
		ret += std::to_string(datalen);
		ret += " data=";
		for (size_t i = 0; i < MIN(datalen, 50); ++i)
		{
			if (!std::isprint(data[i]))
			{
				ret += "<binary>";
				return ret;
			}
		}
		ret.append((char*) data, MIN(datalen, 50));
		if (datalen > 50)
		{
			ret += "...";
		}
	}
	return ret;
}

std::vector<sinsp_plugin_cap_sourcing::open_param> sinsp_plugin::list_open_params() const
{
	std::vector<sinsp_plugin_cap_sourcing::open_param> list;
	if(m_state && m_handle->api.list_open_params)
	{
		ss_plugin_rc rc;
		string jsonString = str_from_alloc_charbuf(m_handle->api.list_open_params(m_state, &rc));
		if (rc != SS_PLUGIN_SUCCESS)
		{
			throw sinsp_exception(string("error in plugin ") + name() + ": list_open_params has error " + get_last_error());
		}

		if (jsonString.size() > 0)
		{
			Json::Value root;
			if(Json::Reader().parse(jsonString, root) == false || root.type() != Json::arrayValue)
			{
				throw sinsp_exception(string("error in plugin ") + name() + ": list_open_params returned a non-array JSON");
			}
			for(Json::Value::ArrayIndex i = 0; i < root.size(); i++)
			{
				open_param param;
				param.value = root[i]["value"].asString();
				if(param.value == "")
				{
					throw sinsp_exception(string("error in plugin ") + name() + ": list_open_params has entry with no value");
				}
				param.desc = root[i]["desc"].asString();
				param.separator = root[i]["separator"].asString();
				list.push_back(param);
			}
		}
	}

	return list;
}

/** End of Event Source CAP **/

/** Extractor CAP **/

const std::set<std::string> &sinsp_plugin::extract_event_sources() const
{
	return m_extract_event_sources;
}

const std::vector<filtercheck_field_info>& sinsp_plugin::fields() const
{
	return m_fields;
}

sinsp_filter_check* sinsp_plugin::new_filtercheck(std::shared_ptr<sinsp_plugin> plugin)
{
	return new sinsp_filter_check_plugin(plugin);
}

bool sinsp_plugin::extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields) const
{
	if(!m_state)
	{
		return false;
	}

	return m_handle->api.extract_fields(m_state, &evt, num_fields, fields) == SS_PLUGIN_SUCCESS;
}

bool sinsp_plugin::is_source_compatible(const std::string &source) const
{
	if (m_extract_event_sources.size() == 0)
	{
		if (m_caps & CAP_SOURCING)
		{
			//
			// If this is a plugin with event sourcing capabilities, reject events that have
			// not been generated by a plugin with this id specifically.
			//
			return source == m_event_source;
		}
		return true;
	}
	return m_extract_event_sources.find(source) != m_extract_event_sources.end();
}

/** **/
