/*
Copyright (C) 2013-2020 Draios Inc dba Sysdig.

This file is part of sysdig.

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

//
// This file contains the prototype and type definitions of sinsp/scap plugins
//

//
// Plugin types
//
typedef enum ss_plugin_type
{
	TYPE_SOURCE_PLUGIN = 1,
	TYPE_EXTRACTOR_PLUGIN = 2
}ss_plugin_type;

//
// This is the opaque pointer to the state of a source plugin.
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
// Interface of a sinsp/scap plugin
//
typedef struct
{
	//
	// Initialize the plugin and, if needed, allocate its state.
	//
	ss_plugin_t* (*init)(char* config, int32_t* rc);
	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	//
	void (*destroy)(ss_plugin_t* s);
	//
	// Return a string with the error that was last generated by the plugin.
	//
	char* (*get_last_error)();
	//
	// Return the plugin type.
	// Currently accepted types are:
	//  TYPE_SOURCE_PLUGIN = 1
	//  TYPE_EXTRACTOR_PLUGIN = 2
	//
	// Source plugins implement a new sinsp/scap event source and MUST export: 
	// get_type, get_last_error, get_id, get_name, get_description, open, close,
	// next and event_to_string. They can optionally also export init, destory, 
	// get_fields and extract_str.
	//
	// Extractor plugins focus on  MUST export: get_type, get_last_error, get_name, 
	// get_description, get_fields and extract_str
	// They can optionally also export init and destory.
	//
	uint32_t (*get_type)();
	//
	// Return the unique ID of the plugin.
	// EVERY SOURCE PLUGIN (see get_type()) MUST OBTAIN AN OFFICIAL ID FROM THE 
	// FALCO ORGANIZATION, OTHERWISE IT WON'T PROPERLY COEXIST WITH OTHER PLUGINS.
	//
	uint32_t (*get_id)();
	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	//
	char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	//
	char* (*get_description)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in falco rules and sysdig filters.
	// This method returns a string with the list of fields encoded as a json
	// array.
	//
	char* (*get_fields)();
	//
	// Open the source and start a capture.
	// Arguments:
	// - s: the plugin state returned by init()
	// - params: the open parameters, as a string. The format is defined by the plugin 
	//   itsef
	// - rc: pointer to an integer that will contain the open result, as a SCAP_* value 
	//   (e.g. SCAP_SUCCESS=0, SCAP_FAILURE=1)
	// Return value: a pointer to the open context that will be passed to next(), 
	// close(), event_to_string() and extract_as_*.
	//
	ss_instance_t* (*open)(ss_plugin_t* s, char* params, int32_t* rc);
	//
	// Close a capture.
	// Arguments:
	// - s: the plugin context, returned by init(). Can be NULL.
	// - h: the capture context, returned by open(). Can be NULL.
	//
	void (*close)(ss_plugin_t* s, ss_instance_t* h);
	//
	// Return the next event.
	// Arguments:
	// - s: the plugin context, returned by init(). Can be NULL.
	// - h: the capture context, returned by open(). Can be NULL.
	// - data: pointer to a memory buffer pointer. The plugin will set it to point to 
	//   the memory containing the next event.
	// - datalen: pointer to a 32bit integer. The plugin will set it the size of the
	//   buffer pointed by data
	// Return value: the status of the operation (e.g. SCAP_SUCCESS=0, SCAP_FAILURE=1,
	// SCAP_TIMEOUT=-1)
	//
	int32_t (*next)(ss_plugin_t* s, ss_instance_t* h, uint8_t** data, uint32_t* datalen);
	//
	// Return a text representation of an event generated by this source plugin.
	// Arguments:
	// - data: the buffer produced by next().
	// - datalen: the length of the buffer produced by next().
	// Return value: the text representation of the event This is used, for example, 
	// by sysdig to print a line for the given event.
	//
	char* (*event_to_string)(uint8_t* data, uint32_t datalen);
	//
	// Extract a filter field value from an event, as a string.
	// Arguments:
	// - evtnum: the number of the event that is bein processed
	// - id: the numeric identifier of the field to extract. It corresponds to the
	//   position of the field in the array returned by get_fields().
	// - arg: the field argument, if an argument has been specified for the field,
	//   otherwise it's NULL. For example:
	//    * if the field specified by the user is foo.bar[pippo], arg will be the 
	//      string "pippo"
	//    * if the field specified by the user is foo.bar, arg will be NULL
	// - data: the buffer produced by next().
	// - datalen: the length of the buffer produced by next().
	// Return value: the string value of the filter field.
	//
	char* (*extract_str)(uint64_t evtnum, uint32_t id, char* arg, uint8_t* data, uint32_t datalen);

	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	ss_plugin_t* state;
	ss_instance_t* handle;
	uint32_t id;
} ss_plugin_info;
