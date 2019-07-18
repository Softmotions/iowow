include(CheckSymbolExists)

if (NOT CMAKE_BUILD_TYPE)
    message(FATAL_ERROR "Please specify the build type -DCMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo")
endif()

set(MODULES log utils platform fs rdb kv)

set(PROJECT_LLIBRARIES)
set(PROJECT_INCLUDE_DIRS)
set(ALL_SRC)
set(ALL_HDRS)
set(PUB_HDRS)
set(PROJECT_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
list(APPEND PROJECT_INCLUDE_DIRS "${PROJECT_GENERATED_DIR}"
                                  "${CMAKE_CURRENT_SOURCE_DIR}")

if(APPLE)
    option(BUILD_FRAMEWORK "Build an OS X framework" OFF)
    set(FRAMEWORK_INSTALL_DIR "/Library/Frameworks" CACHE STRING "Directory to install frameworks to.")
endif()

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(TestBigEndian)

if (OWNER_PROJECT_NAME)
  set(IW_PUBLIC_HEADER_DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${OWNER_PROJECT_NAME}/${PROJECT_NAME})
else()
  set(IW_PUBLIC_HEADER_DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
endif()

if ((CMAKE_BUILD_TYPE EQUAL Release) OR (CMAKE_BUILD_TYPE EQUAL RelWithDebInfo))
  add_definition(-DIW_RELEASE)
endif()

TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if (IS_BIG_ENDIAN EQUAL 1)
  add_definitions(-DIW_BIGENDIAN)
endif()

if(CMAKE_SIZEOF_VOID_P MATCHES 8)
  add_definitions(-DIW_64)
else()
  add_definitions(-DIW_32)
endif()

if (BUILD_TESTS)
 add_definitions(-DIW_TESTS=1)
endif()

find_package(Threads REQUIRED CMAKE_THREAD_PREFER_PTHREAD)
if (CMAKE_USE_WIN32_THREADS_INIT)
    add_definitions(-DIW_WIN32_THREADS)
elseif (CMAKE_USE_PTHREADS_INIT)
    add_definitions(-DIW_PTHREADS)
    check_library_exists(pthread pthread_condattr_setclock "" HAVE_PTHREAD_CONDATTR_SETCLOCK)
    if (HAVE_PTHREAD_CONDATTR_SETCLOCK)
      add_definitions(-DIW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
    endif()
else()
    mesage(FATAL_ERROR "Unable to find suitable threading library")
endif(CMAKE_USE_WIN32_THREADS_INIT)

if (NOT WIN32)
  list(APPEND PROJECT_LLIBRARIES ${CMAKE_THREAD_LIBS_INIT})
else()
  include(Win32LIBTools)
  check_include_file(windows.h HAVE_WINDOWS_H)
	if (NOT HAVE_WINDOWS_H)
		message(FATAL_ERROR "Unable to find windows.h include file")
	endif()

  set(IBERTY_FIND_REQUIRED ON)
  include(FindLibIberty)
  list(APPEND PROJECT_LLIBRARIES ${IBERTY_LIBRARIES})

  check_library_exists(winpthread pthread_exit "" HAVE_WINPTHREAD)
	if (NOT HAVE_WINPTHREAD)
		message(FATAL_ERROR "Unable to winpthread lib")
	endif()
	list(INSERT PROJECT_LLIBRARIES 0 -lwinpthread)
  add_definitions(-D_POSIX_THREAD_SAFE_FUNCTIONS)
endif()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "mips")
  include(FindAtomic)
  if (ATOMIC_FOUND)
    list(APPEND PROJECT_LLIBRARIES "${ATOMIC_LIBRARY}")
  endif()
endif()

find_library(M_LIB m)
if (NOT M_LIB)
	message(FATAL_ERROR "Library 'libm' not FOUND")
endif(NOT M_LIB)
list(APPEND PROJECT_LLIBRARIES "${M_LIB}")

check_symbol_exists(CLOCK_MONOTONIC time.h HAVE_CLOCK_MONOTONIC)
if (HAVE_CLOCK_MONOTONIC)
  add_definitions(-DIW_HAVE_CLOCK_MONOTONIC)
endif()

foreach(HF IN ITEMS stdlib stddef stdint stdbool stdatomic unistd dirent)
    string(TOUPPER "${HF}" UHF)
    check_include_file(${HF}.h "IW_HAVE_${UHF}")
    if (NOT IW_HAVE_${UHF})
        message(FATAL_ERROR "Include file '${HF}.h' not FOUND")
    endif()
endforeach(HF)

add_definitions(-D_GNU_SOURCE)
add_definitions(-D_LARGEFILE_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)

list(APPEND ALL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/iowow.c)

foreach(MODULE IN LISTS MODULES)
    file(GLOB MODULE_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.c)
    file(GLOB MODULE_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.h)
    list(APPEND ALL_SRC ${MODULE_SRC})
    list(APPEND ALL_HDRS ${MODULE_HDRS})
    list(APPEND PROJECT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE})
endforeach(MODULE)

list(APPEND PUB_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/basedefs.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/iowow.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/log/iwlog.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/fs/iwdlsnr.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/fs/iwfile.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/fs/iwexfile.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/fs/iwfsmfile.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/rdb/iwrdb.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/kv/iwkv.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/platform/iwp.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwutils.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwuuid.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwxstr.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwconv.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwbits.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwarr.h
                     ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwpool.h
                     )

list(REMOVE_DUPLICATES PROJECT_LLIBRARIES)
list(REMOVE_DUPLICATES PROJECT_INCLUDE_DIRS)
include_directories(${PROJECT_INCLUDE_DIRS})

# -pg -no-pie
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
                    -std=gnu11 -fsigned-char -pedantic \
                    -Wfatal-errors -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter \
                    -Wno-unknown-pragmas -Wno-unused-function -Wno-missing-field-initializers \
                    -Wno-missing-braces")
if (NOT WIN32) ## todo review
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
else()
    add_definitions(-D__USE_MINGW_ANSI_STDIO)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pedantic-ms-format")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()

if (ASAN)
  set(CMAKE_C_ASAN "-fsanitize=address -fno-omit-frame-pointer")
endif()

set(CMAKE_C_FLAGS_DEBUG "-O0 -g -ggdb -Werror -DDEBUG -D_DEBUG -UNDEBUG \
                         -Wno-unused-variable ${CMAKE_C_ASAN}")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG ${CMAKE_C_ASAN}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -g")


if (CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
endif()

if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif(CMAKE_COMPILER_IS_GNUCC)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/tmpl/iwcfg.h ${PROJECT_GENERATED_DIR}/iwcfg.h)
file(GLOB PROJECT_GENERATED_HDRS ${PROJECT_GENERATED_DIR}/*.h)
list(APPEND ALL_HDRS ${PROJECT_GENERATED_HDRS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/tmpl/libiowow.pc.in ${PROJECT_GENERATED_DIR}/libiowow.pc @ONLY)
install(FILES ${PROJECT_GENERATED_DIR}/libiowow.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

foreach(MODULE IN LISTS MODULES)
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/CMakeLists.txt)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE})
    endif()
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tools/CMakeLists.txt)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tools)
    endif()
    if (BUILD_TESTS AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tests/CMakeLists.txt)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tests)
    endif()
    if (BUILD_EXAMPLES AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/examples/CMakeLists.txt)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/examples)
    endif()
    if (BUILD_BENCHMARKS AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/benchmark/CMakeLists.txt)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/benchmark)
    endif()
endforeach(MODULE)

if (NOT BUILD_SHARED_LIBS)
    add_definitions(-DIW_NODLL)
    add_library(iowow STATIC ${ALL_SRC})
    add_library(iowow_s ALIAS iowow)
else()
    add_library(iowow SHARED ${ALL_SRC})
    add_library(iowow_s STATIC ${ALL_SRC})
endif()

target_link_libraries(iowow ${PROJECT_LLIBRARIES})
if (BUILD_SHARED_LIBS)
    target_link_libraries(iowow_s ${PROJECT_LLIBRARIES})
endif()

if (BUILD_SHARED_LIBS)
    if (WIN32)
      add_dependencies(iowow wintools_init)
      set_target_properties(iowow PROPERTIES LINK_FLAGS "-Wl,--output-def,libiowow.def")
      add_w32_importlib(iowow libiowow ${CMAKE_CURRENT_BINARY_DIR})
      install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/libiowow.def
        ${CMAKE_CURRENT_BINARY_DIR}/libiowow.lib
        ${CMAKE_CURRENT_BINARY_DIR}/libiowow.exp
              DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif(WIN32)

    set_target_properties(iowow PROPERTIES
                          VERSION ${PROJECT_VERSION}
                          SOVERSION ${PROJECT_VERSION_MAJOR}
                          PUBLIC_HEADER "${PUB_HDRS}"
                          DEFINE_SYMBOL IW_API_EXPORTS)

    set_target_properties(iowow_s PROPERTIES
                          VERSION ${PROJECT_VERSION}
                          COMPILE_FLAGS "-DIW_NODLL"
                          OUTPUT_NAME iowow-${PROJECT_VERSION_MAJOR})
else()

    set_target_properties(iowow PROPERTIES
                          VERSION ${PROJECT_VERSION}
                          PUBLIC_HEADER "${PUB_HDRS}"
                          COMPILE_FLAGS "-DIW_NODLL"
                          OUTPUT_NAME iowow-${PROJECT_VERSION_MAJOR})
endif(BUILD_SHARED_LIBS)

install(TARGETS iowow
        EXPORT iowow-exports
        FRAMEWORK DESTINATION ${FRAMEWORK_INSTALL_DIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${IW_PUBLIC_HEADER_DESTINATION})

install(EXPORT iowow-exports
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME})

if (BUILD_SHARED_LIBS)
    install(TARGETS iowow_s
        EXPORT iowow-static-exports
        FRAMEWORK DESTINATION ${FRAMEWORK_INSTALL_DIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${IW_PUBLIC_HEADER_DESTINATION})

    install(EXPORT iowow-static-exports
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME})
endif()


install(FILES
        ${CMAKE_SOURCE_DIR}/LICENSE
        ${CMAKE_SOURCE_DIR}/Changelog
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES
        ${CMAKE_SOURCE_DIR}/README.md
        RENAME README
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

if (CMAKE_VERSION VERSION_GREATER 3.0)
    export(EXPORT iowow-exports)
  if (BUILD_SHARED_LIBS)
    export(EXPORT iowow-static-exports)
  endif(BUILD_SHARED_LIBS)
else()
  export(TARGETS iowow FILE iowow-exports.cmake)
  if (BUILD_SHARED_LIBS)
    export(TARGETS iowow_s FILE iowow-static-exports.cmake)
  endif(BUILD_SHARED_LIBS)
endif()

include(InstallRequiredSystemLibraries)

set(${PROJECT_NAME}_PUB_HDRS ${PUB_HDRS}
    CACHE INTERNAL "${PROJECT_NAME}: Public headers" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_INCLUDE_DIRS}
    CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)

message("")
message("${PROJECT_NAME} LINK LIBS: ${PROJECT_LLIBRARIES}")
message("\n${PROJECT_NAME} INCLUDE DIRS: ${PROJECT_INCLUDE_DIRS}")
message("\n${PROJECT_NAME} SOURCES: ${ALL_SRC}")
message("\n${PROJECT_NAME} PUB_HDRS: ${PUB_HDRS}")
message("\n${PROJECT_NAME} CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message("${PROJECT_NAME} BUILD_SHARED_LIBS: ${BUILD_SHARED_LIBS}")
message("${PROJECT_NAME} BUILD_TESTS: ${BUILD_TESTS}")
message("${PROJECT_NAME} BUILD_EXAMPLES: ${BUILD_EXAMPLES}")
message("${PROJECT_NAME} BUILD_BENCHMARKS: ${BUILD_BENCHMARKS}")
message("${PROJECT_NAME} BUILD_DOCUMENTATION: ${BUILD_DOCUMENTATION}")
message("${PROJECT_NAME} PUBLIC_HEADER_DESTINATION: ${IW_PUBLIC_HEADER_DESTINATION}")
