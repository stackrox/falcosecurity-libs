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
#pragma once

#define SINSP_PUBLIC

#ifndef ASSERT

#include <assert.h>

// We expect the global g_logger be provided from the outside
class sinsp_logger;
extern sinsp_logger g_logger;

#ifdef _DEBUG

#ifdef _WIN32
#include <cassert>
#endif

#ifdef ASSERT_TO_LOG
#define ASSERT(X) do {								\
	if(!(X)) 										\
	{ 												\
		g_logger.format(sinsp_logger::SEV_DEBUG, 	\
						"ASSERTION %s at %s:%d", 	\
						#X , __FILE__, __LINE__); 	\
	} 												\
} while(0)
#else // ASSERT_TO_LOG
#define ASSERT(X) assert(X);
#endif // ASSERT_TO_LOG

#else // _DEBUG

#ifdef ASSERT_TO_LOG
#define ASSERT(X) do { 								\
	if(!(X)) 										\
	{ 												\
		g_logger.format(sinsp_logger::SEV_DEBUG, 	\
						"ASSERTION %s at %s:%d", 	\
						#X , __FILE__, __LINE__); 	\
	} 												\
} while(0)
#else
#define ASSERT(X)
#endif // ASSERT_TO_LOG

#endif // _DEBUG
#endif // ASSERT
