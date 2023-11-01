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

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <assert.h>

#include "falcosecurity/log.h"

#ifndef ASSERT

#ifdef _DEBUG

#ifdef ASSERT_TO_LOG
#define ASSERT(X) if(!(X)) \
{ 					\
	char buf[256]; 	\
	snprintf(buf, sizeof(buf), "ASSERTION " #X " at %s:%d", __FILE__, __LINE__); \
	logger_fn("libscap", buf, FALCOSECURITY_LOG_SEV_ERROR); \
}
#else // ASSERT_TO_LOG
#define ASSERT(X) assert(X)
#endif // ASSERT_TO_LOG

#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

#endif // ASSERT
