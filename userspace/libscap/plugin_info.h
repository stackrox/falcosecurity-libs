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

#pragma once

#include "../plugin/plugin_api.h"

//
// This file contains the prototype and type definitions of sinsp/scap plugins
//

//
// There are two plugin types: source plugins and extractor plugins.
//
// Source plugins implement a new sinsp/scap event source and have the
// ability to provide events to the event loop. Optionally, they can
// extract fields from events so they can be displayed/used in
// filters.
//
// Extractor plugins do not provide events, but have the ability to
// extract fields from events created by other plugins. A good example
// of an extractor plugin is a json extractor, which can extract
// information from any json payload, regardless of where the payloads
// come from.
//
typedef enum ss_plugin_type
{
	TYPE_SOURCE_PLUGIN = 1,
	TYPE_EXTRACTOR_PLUGIN = 2
}ss_plugin_type;

// The noncontinguous numbers are to maintain equality with underlying
// falcosecurity libs types.
typedef enum ss_plugin_field_type
{
	FTYPE_UINT64 = 8,
	FTYPE_STRING = 9
}ss_plugin_field_type;

// Values to return from init() / open() / next_batch() /
// extract_fields().
typedef enum ss_plugin_rc
{
	SS_PLUGIN_SUCCESS = 0,
	SS_PLUGIN_FAILURE = 1,
	SS_PLUGIN_TIMEOUT = -1,
	SS_PLUGIN_EOF = 2,
	SS_PLUGIN_NOT_SUPPORTED = 3,
} ss_plugin_rc;

// This struct represents an event returned by the plugin, and is used
// below in next_batch().
// - evtnum: incremented for each event returned. Might not be contiguous.
// - data: pointer to a memory buffer pointer. The plugin will set it
//   to point to the memory containing the next event.
// - datalen: pointer to a 32bit integer. The plugin will set it the size of the
//   buffer pointed by data.
// - ts: the event timestamp, in nanoseconds since the epoch.
//   Can be (uint64_t)-1, in which case the engine will automatically
//   fill the event time with the current time.
//
// Note: event numbers are assigned by the plugin
// framework. Therefore, there isn't any need to fill in evtnum when
// returning an event via plugin_next_batch. It will be ignored.
typedef struct ss_plugin_event
{
	uint64_t evtnum;
	const uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;

// Used in extract_fields functions below to receive a field/arg
// pair and return an extracted value.
// field_id: id of the field, as of its index in the list of
//           fields specified by the plugin.
// field: the field name.
// arg: the field argument, if an argument has been specified
//      for the field, otherwise it's NULL.
//      For example:
//         * if the field specified by the user is foo.bar[pippo], arg will be the
//           string "pippo"
//         * if the field specified by the user is foo.bar, arg will be NULL
// ftype: the type of the field. Could be derived from the field name alone,
//   but including here can prevent a second lookup of field names.
// The following should be filled in by the extraction function:
// - field_present: set to true if the event has a meaningful
//   extracted value for the provided field, false otherwise
// - res_str: if the corresponding field was type==string, this should be
//   filled in with the string value. The string must be allocated and set
//   by the plugin.
// - res_u64: if the corresponding field was type==uint64, this should be
//   filled in with the uint64 value.

typedef struct ss_plugin_extract_field
{
	uint32_t field_id;
	const char* field;
	const char* arg;
	uint32_t ftype;

	bool field_present;
	const char* res_str;
	uint64_t res_u64;
} ss_plugin_extract_field;

//
// This is the opaque pointer to the state of a plugin.
// It points to any data that might be needed plugin-wise. It is
// allocated by init() and must be destroyed by destroy().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_plugin_t;

//
// This is the opaque pointer to the state of an open instance of the source
// plugin.
// It points to any data that is needed while a capture is running. It is
// allocated by open() and must be destroyed by close().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_instance_t;

//
// The structs below define the functions and arguments for source and
// extractor plugins. The structs are used by the plugin framework to
// load and interface with plugins.
//
// From the perspective of the plugin, each function below should be
// exported from the dynamic library as a C calling convention
// function, adding a prefix "plugin_" to the function name
// (e.g. plugin_get_required_api_version, plugin_init, etc.)
//
// Plugins are totally responsible of both allocating and deallocating memory.
// Plugins have the guarantee that they can safely deallocate memory in
// these cases:
// - During close(), for all the memory allocated in the context of a plugin
//   instance after open().
// - During destroy(), for all the memory allocated by the plugin, as it stops
//   being executed.
// - During subsequent calls to the same function, for all the exported
//   functions returning memory pointers.
//
// Plugins must not free memory passed in by the framework (i.e. function input
// parameters) if not corresponding to plugin-allocated memory in the
// cases above. Plugins can safely use the passed memory during the execution
// of the exported functions.

//
// Interface for a sinsp/scap source plugin.
//
typedef struct
{
	uint32_t id;
	const char *name;
	ss_plugin_t *state;
	ss_instance_t *handle;

	ss_instance_t* (*open)(ss_plugin_t* s, const char* params, ss_plugin_rc* rc);
	void (*close)(ss_plugin_t* s, ss_instance_t* h);
	ss_plugin_rc (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts);
	const char *(*get_last_error)(ss_plugin_t *s);
} scap_source_plugin;
