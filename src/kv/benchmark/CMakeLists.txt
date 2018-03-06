include(ExternalProject)
include(ProcessorCount)
ProcessorCount(PROCESSOR_COUNT_VAL)

# IWKV benchmark
add_executable(iwkv_benchmark iwkv_benchmark.c)
target_link_libraries(iwkv_benchmark iowow_s)
set_target_properties(iwkv_benchmark PROPERTIES COMPILE_FLAGS "-DIW_STATIC")

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
set(LEVELDB_SOURCE_DIR "${CMAKE_BINARY_DIR}/src/leveldb")
set(LEVELDB_BINARY_DIR "${CMAKE_BINARY_DIR}/src/leveldb")
add_library(libleveldb STATIC IMPORTED)
set_target_properties(libleveldb PROPERTIES IMPORTED_LOCATION "${LEVELDB_BINARY_DIR}/out-static/libleveldb.a")
add_dependencies(libleveldb extern_leveldb)
list(APPEND PROJECT_INCLUDE_DIRS "${LEVELDB_SOURCE_DIR}/include")
## !LevelDB


# LevelDB benchmark

