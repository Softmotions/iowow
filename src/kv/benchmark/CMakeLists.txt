include(ExternalProject)
include(ProcessorCount)
ProcessorCount(PROCESSOR_COUNT_VAL)

# IWKV benchmark
add_executable(iwkv_benchmark iwkv_benchmark.c)
target_link_libraries(iwkv_benchmark iowow_s)
set_target_properties(iwkv_benchmark PROPERTIES COMPILE_FLAGS "-DIW_STATIC")

enable_language(CXX)

## LevelDB
ExternalProject_Add(
  extern_leveldb
  GIT_REPOSITORY https://github.com/google/leveldb.git
  GIT_TAG v1.20
  PREFIX ${CMAKE_BINARY_DIR}
  BUILD_IN_SOURCE ON
  GIT_PROGRESS ON
  UPDATE_DISCONNECTED ON
  BUILD_COMMAND make -j${PROCESSOR_COUNT_VAL}
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND ""
  LOG_DOWNLOAD ON
  LOG_BUILD ON
)
set(LEVELDB_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/extern_leveldb")
set(LEVELDB_BINARY_DIR "${CMAKE_BINARY_DIR}/src/extern_leveldb")
add_library(libleveldb STATIC IMPORTED)
set_target_properties(
  libleveldb
  PROPERTIES
  IMPORTED_LOCATION "${LEVELDB_BINARY_DIR}/out-static/libleveldb.a"
  IMPORTED_LINK_INTERFACE_LANGUAGES CXX
)
add_dependencies(libleveldb extern_leveldb)
include_directories(AFTER "${LEVELDB_SOURCE_DIR}/include")
## !LevelDB

# LevelDB benchmark
add_executable(leveldb_benchmark leveldb_benchmark.c)
target_link_libraries(leveldb_benchmark libleveldb iowow_s)
set_target_properties(leveldb_benchmark
  PROPERTIES COMPILE_FLAGS "-DIW_STATIC"
)

# LMDB
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
)
set(LMDB_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/extern_lmdb")
set(LMDB_BINARY_DIR "${CMAKE_BINARY_DIR}/src/extern_lmdb")
add_library(liblmdb STATIC IMPORTED)
set_target_properties(
  liblmdb
  PROPERTIES
  IMPORTED_LOCATION "${LMDB_BINARY_DIR}/libraries/liblmdb/liblmdb.a"
)
add_dependencies(liblmdb extern_lmdb)
include_directories(AFTER "${LMDB_SOURCE_DIR}/libraries/liblmdb")

# LMDB benchmark
add_executable(lmdb_benchmark lmdb_benchmark.c)
target_link_libraries(lmdb_benchmark liblmdb iowow_s)
set_target_properties(lmdb_benchmark
  PROPERTIES COMPILE_FLAGS "-DIW_STATIC"
)

# KyotoCabinet
ExternalProject_Add(
  extern_kyc
  URL https://fallabs.com/kyotocabinet/pkg/kyotocabinet-1.2.77.tar.gz
  PREFIX ${CMAKE_BINARY_DIR}
  BUILD_IN_SOURCE ON
  UPDATE_DISCONNECTED ON
  BUILD_COMMAND make
  CONFIGURE_COMMAND ./configure --disable-zlib --prefix=${CMAKE_BINARY_DIR}/src/extern_kyc/install
  INSTALL_COMMAND make install
  LOG_DOWNLOAD ON
  LOG_BUILD OFF
  LOG_CONFIGURE OFF
)
set(KYC_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/extern_kyc")
set(KYC_BINARY_DIR "${CMAKE_BINARY_DIR}/src/extern_kyc")
add_library(libkyotocabinet STATIC IMPORTED)
set_target_properties(
  libkyotocabinet
  PROPERTIES
  IMPORTED_LOCATION "${KYC_BINARY_DIR}/install/lib/libkyotocabinet.a"
  IMPORTED_LINK_INTERFACE_LANGUAGES CXX
)
add_dependencies(libkyotocabinet extern_kyc)
include_directories(AFTER "${KYC_BINARY_DIR}/install/include")

add_executable(kyc_benchmark kyc_benchmark.c)
target_link_libraries(kyc_benchmark libkyotocabinet iowow_s)
set_target_properties(kyc_benchmark
  PROPERTIES COMPILE_FLAGS "-DIW_STATIC"
)

# TokyoCabinet
ExternalProject_Add(
  extern_tc
  URL https://fallabs.com/tokyocabinet/tokyocabinet-1.4.48.tar.gz
  PREFIX ${CMAKE_BINARY_DIR}
  BUILD_IN_SOURCE ON
  UPDATE_DISCONNECTED ON
  BUILD_COMMAND make
  CONFIGURE_COMMAND ./configure --disable-bzip --disable-exlzo --disable-exlzma --disable-zlib --prefix=${CMAKE_BINARY_DIR}/src/extern_tc/install
  INSTALL_COMMAND make install
  LOG_DOWNLOAD ON
  LOG_BUILD OFF
  LOG_CONFIGURE OFF
)
set(TC_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/extern_tc")
set(TC_BINARY_DIR "${CMAKE_BINARY_DIR}/src/extern_tc")
add_library(libtokyocabinet STATIC IMPORTED)
set_target_properties(
  libtokyocabinet
  PROPERTIES
  IMPORTED_LOCATION "${TC_BINARY_DIR}/install/lib/libtokyocabinet.a"
  IMPORTED_LINK_INTERFACE_LANGUAGES C
)
add_dependencies(libtokyocabinet extern_tc)
include_directories(AFTER "${TC_BINARY_DIR}/install/include")

add_executable(tc_benchmark tc_benchmark.c)
target_link_libraries(tc_benchmark libtokyocabinet iowow_s)
set_target_properties(tc_benchmark
  PROPERTIES COMPILE_FLAGS "-DIW_STATIC"
)

# Wiredtiger
set(WT_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/extern_wt")
set(WT_BINARY_DIR "${CMAKE_BINARY_DIR}/src/extern_wt")
ExternalProject_Add(
  extern_wt
  GIT_REPOSITORY https://github.com/wiredtiger/wiredtiger.git
  PREFIX ${WT_BINARY_DIR}
  BUILD_IN_SOURCE ON
  UPDATE_DISCONNECTED ON
  CONFIGURE_COMMAND sh -c "test -f ${WT_BINARY_DIR}/install/include/wiredtiger.h || (./autogen.sh && ./configure --prefix=${WT_BINARY_DIR}/install)"
  BUILD_COMMAND ""
  INSTALL_COMMAND sh -c "test -f ${WT_BINARY_DIR}/install/include/wiredtiger.h || make install"
  LOG_DOWNLOAD ON
  LOG_BUILD OFF
  LOG_CONFIGURE OFF
)
add_library(libwiredtiger STATIC IMPORTED)
set_target_properties(
  libwiredtiger
  PROPERTIES
  IMPORTED_LOCATION "${WT_BINARY_DIR}/install/lib/libwiredtiger.a"
  IMPORTED_LINK_INTERFACE_LANGUAGES C
)
add_dependencies(libwiredtiger extern_wt)
include_directories(AFTER "${WT_BINARY_DIR}/install/include")

add_executable(wiredtiger_benchmark wiredtiger_benchmark.c)
target_link_libraries(wiredtiger_benchmark libwiredtiger iowow_s "-ldl")
set_target_properties(wiredtiger_benchmark
  PROPERTIES COMPILE_FLAGS "-DIW_STATIC"
)

# BDB 5.3
find_library(BDB_LIBRARY NAMES db)
if (BDB_LIBRARY)
  add_executable(bdb_benchmark bdb_benchmark.c)
  target_link_libraries(bdb_benchmark db iowow_s)
endif()


