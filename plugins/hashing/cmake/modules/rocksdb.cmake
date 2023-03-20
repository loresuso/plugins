if(NOT ALLOCATOR STREQUAL "jemalloc")
  set(ROCKSDB_JEMALLOC "DISABLE_JEMALLOC=1")
endif()

set(ROCKSDB_EXTRA_CXXFLAG "-fPIC -Wno-unused-variable")
if(NOT CMAKE_BUILD_TYPE STREQUAL Debug)
  set(ROCKSDB_EXTRA_CXXFLAG "${ROCKSDB_EXTRA_CXXFLAG} -DNDEBUG")
endif(NOT CMAKE_BUILD_TYPE STREQUAL Debug)

set(ROCKSDB_CXX "${CMAKE_CXX_COMPILER}")
if (WITH_CCACHE AND CCACHE_FOUND)
  set(ROCKSDB_CXX "ccache ${CMAKE_CXX_COMPILER}")
endif(WITH_CCACHE AND CCACHE_FOUND)

set(ROCKSDB_AR "${CMAKE_AR}")

include(ExternalProject)
ExternalProject_Add(rocksdb_ext
    URL "https://github.com/facebook/rocksdb/archive/refs/tags/v8.0.0.tar.gz"
    PREFIX "rocksdb"
    PATCH_COMMAND ""
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND PORTABLE=1 ${ROCKSDB_JEMALLOC} $(MAKE) CXX=${ROCKSDB_CXX} AR=${ROCKSDB_AR} EXTRA_CXXFLAGS=${ROCKSDB_EXTRA_CXXFLAG} static_lib
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")

# force rocksdb make to be called on each time
# ExternalProject_Add_Step(rocksdb_ext forcebuild DEPENDEES configure DEPENDERS build ALWAYS 1)

ExternalProject_Get_Property(rocksdb_ext source_dir)
set(ROCKSDB_INCLUDE_DIR ${source_dir}/include)

# add a imported library for librocksdb.a
add_library(rocksdb STATIC IMPORTED)
target_link_libraries(rocksdb)
add_dependencies(rocksdb rocksdb_ext)
set_property(TARGET rocksdb PROPERTY IMPORTED_LOCATION "${source_dir}/librocksdb.a")

include_directories(${ROCKSDB_INCLUDE_DIR})