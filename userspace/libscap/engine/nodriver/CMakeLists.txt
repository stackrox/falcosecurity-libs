include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_nodriver nodriver.c)
target_link_libraries(scap_engine_nodriver scap_engine_noop)
set_target_properties(scap_engine_nodriver PROPERTIES COMPILE_FLAGS "-fPIC")
