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
# IWKV benchmark
add_executable(leveldb_benchmark leveldb_benchmark.c)
target_link_libraries(leveldb_benchmark libleveldb iowow_s)
set_target_properties(leveldb_benchmark
  PROPERTIES COMPILE_FLAGS "-DIW_STATIC"
)
