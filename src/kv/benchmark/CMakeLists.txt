include(ExternalProject)
include(ProcessorCount)
ProcessorCount(PROCESSOR_COUNT_VAL)

# IWKV benchmark
add_executable(iwkv_benchmark iwkv_benchmark.c)
target_link_libraries(iwkv_benchmark iowow_s)
set_target_properties(iwkv_benchmark PROPERTIES COMPILE_FLAGS "-DIW_STATIC")

enable_language(CXX)

# LevelDB
ExternalProject_Add(
  extern_leveldb
  GIT_REPOSITORY https://github.com/google/leveldb.git
  GIT_TAG 1.23
  PREFIX ${CMAKE_BINARY_DIR}
  CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}"
  BUILD_IN_SOURCE OFF
  GIT_PROGRESS ON
  UPDATE_DISCONNECTED ON
  LOG_DOWNLOAD ON
  LOG_BUILD ON
  BUILD_BYPRODUCTS "${CMAKE_BINARY_DIR}/lib/libleveldb.a")
add_library(libleveldb STATIC IMPORTED)
set_target_properties(
  libleveldb
  PROPERTIES IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/lib/libleveldb.a"
             IMPORTED_LINK_INTERFACE_LANGUAGES CXX)
add_dependencies(libleveldb extern_leveldb)
include_directories(AFTER "${CMAKE_BINARY_DIR}/include")
# !LevelDB

# LevelDB benchmark
add_executable(leveldb_benchmark leveldb_benchmark.c)
target_link_libraries(leveldb_benchmark libleveldb iowow_s)
set_target_properties(leveldb_benchmark PROPERTIES COMPILE_FLAGS "-DIW_STATIC")

# LMDB
set(LMDB_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/extern_lmdb")
set(LMDB_BINARY_DIR "${LMDB_SOURCE_DIR}")
ExternalProject_Add(
  extern_lmdb
  GIT_REPOSITORY https://github.com/LMDB/lmdb.git
  GIT_TAG mdb.master
  PREFIX ${CMAKE_BINARY_DIR}
  BUILD_IN_SOURCE ON
  GIT_PROGRESS ON
  UPDATE_DISCONNECTED ON
  BUILD_COMMAND make -C libraries/liblmdb
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND ""
  LOG_DOWNLOAD ON
  LOG_BUILD ON
  BUILD_BYPRODUCTS "${LMDB_BINARY_DIR}/libraries/liblmdb/liblmdb.a")
add_library(liblmdb STATIC IMPORTED)
set_target_properties(
  liblmdb PROPERTIES IMPORTED_LOCATION
                     "${LMDB_BINARY_DIR}/libraries/liblmdb/liblmdb.a")
add_dependencies(liblmdb extern_lmdb)
include_directories(AFTER "${LMDB_SOURCE_DIR}/libraries/liblmdb")

# LMDB benchmark
add_executable(lmdb_benchmark lmdb_benchmark.c)
target_link_libraries(lmdb_benchmark liblmdb iowow_s)
set_target_properties(lmdb_benchmark PROPERTIES COMPILE_FLAGS "-DIW_STATIC")

# Wiredtiger
set(WT_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/extern_wt")
set(WT_BINARY_DIR "${WT_SOURCE_DIR}")
ExternalProject_Add(
  extern_wt
  GIT_REPOSITORY https://github.com/wiredtiger/wiredtiger.git
  PREFIX ${WT_BINARY_DIR}
  BUILD_IN_SOURCE ON
  UPDATE_DISCONNECTED ON
  CONFIGURE_COMMAND
    sh -c
    "test -f ${WT_BINARY_DIR}/install/include/wiredtiger.h || (./autogen.sh && ./configure --prefix=${WT_BINARY_DIR}/install)"
  BUILD_COMMAND ""
  INSTALL_COMMAND
    sh -c
    "test -f ${WT_BINARY_DIR}/install/include/wiredtiger.h || make install"
  LOG_DOWNLOAD ON
  LOG_BUILD OFF
  LOG_CONFIGURE OFF
  BUILD_BYPRODUCTS "${WT_BINARY_DIR}/install/lib/libwiredtiger.a")
add_library(libwiredtiger STATIC IMPORTED)
set_target_properties(
  libwiredtiger
  PROPERTIES IMPORTED_LOCATION "${WT_BINARY_DIR}/install/lib/libwiredtiger.a"
             IMPORTED_LINK_INTERFACE_LANGUAGES C)
add_dependencies(libwiredtiger extern_wt)
include_directories(AFTER "${WT_BINARY_DIR}/install/include")

add_executable(wiredtiger_benchmark wiredtiger_benchmark.c)
target_link_libraries(wiredtiger_benchmark libwiredtiger iowow_s "-ldl")
set_target_properties(wiredtiger_benchmark PROPERTIES COMPILE_FLAGS
                                                      "-DIW_STATIC")

# BDB 5.3
find_library(BDB_LIBRARY NAMES db)
if(BDB_LIBRARY)
  add_executable(bdb_benchmark bdb_benchmark.c)
  target_link_libraries(bdb_benchmark db iowow_s)
endif()
