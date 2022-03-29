if(NOT HAVE_LIBSCAP)
set(HAVE_LIBSCAP On)

if(NOT LIBSCAP_DIR)
	get_filename_component(LIBSCAP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(ExternalProject)

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

get_filename_component(DRIVER_CONFIG_DIR ${CMAKE_BINARY_DIR}/driver/src ABSOLUTE)
get_filename_component(LIBSCAP_INCLUDE_DIR ${LIBSCAP_DIR}/userspace/libscap ABSOLUTE)
set(LIBSCAP_INCLUDE_DIRS ${LIBSCAP_INCLUDE_DIR} ${DRIVER_CONFIG_DIR})

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(KBUILD_FLAGS "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	endif()

    if(NOT DEFINED PROBE_VERSION)
        set(PROBE_VERSION "${SYSDIG_VERSION}")
    endif()
    if(NOT DEFINED PROBE_NAME)
        set(PROBE_NAME "collector")
    endif()

    if(NOT DEFINED PROBE_DEVICE_NAME)
        set(PROBE_DEVICE_NAME "sysdig")
    endif()
endif()

add_subdirectory(${LIBSCAP_DIR}/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)

endif()
