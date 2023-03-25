cmake_minimum_required(VERSION 3.16.1)

project(hashing)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include(rocksdb)
include(json)
include(sdk)

add_library(hashing SHARED 
    hashing.cpp
    hash_calculator.cpp 
    api.cpp 
    watcher.cpp 
    utils.cpp
    lru_cache.cpp
    exec_watcher.cpp)

# todo: create a cmake module also for zlib and openssl
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

target_link_libraries(hashing
    rocksdb
    ZLIB::ZLIB
    nlohmann_json::nlohmann_json 
    pthread 
    ${CMAKE_DL_LIBS}
    crypto
)