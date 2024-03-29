cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")
include(CMakeToolsHelpers OPTIONAL)
set(DEB_CHANGELOG_REQUIRED ON)
set(DEB_CHANGELOG "${CMAKE_CURRENT_SOURCE_DIR}/Changelog")
unset(CHANGELOG_LAST_VERSION)
unset(CHANGELOG_LAST_MESSAGE)
include(DebChangelog)

set(PROJECT_NAME "iowow")
project(${PROJECT_NAME} C)

set(PROJECT_VENDOR "Softmotions (https://softmotions.com)")
set(PROJECT_WEBSITE "https://github.com/Softmotions/iowow")
set(PROJECT_MAINTAINER "Anton Adamansky <adamansky@gmail.com>")
set(PROJECT_DESCRIPTION_SUMMARY "The skiplist based persistent key/value storage engine")
set(PROJECT_DESCRIPTION "The skiplist based persistent key/value storage engine")
set(CHANGELOG_MESSAGE ${CHANGELOG_LAST_MESSAGE})
set(PROJECT_PPA "ppa:adamansky/iowow")
set(PROJECT_PPA_USER "adamansky")
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO")
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "")


set(PROJECT_VERSION_MAJOR ${CHANGELOG_LAST_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${CHANGELOG_LAST_VERSION_MINOR})
set(PROJECT_VERSION_PATCH ${CHANGELOG_LAST_VERSION_PATCH})
set(PROJECT_VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})
set(${PROJECT_NAME}_VERSION ${PROJECT_VERSION})
set(${PROJECT_NAME}_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(${PROJECT_NAME}_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(${PROJECT_NAME}_VERSION_PATCH ${PROJECT_VERSION_PATCH})

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test cases" OFF)
option(ASAN "Turn on address sanitizer" OFF)
option(UBSAN "Turn on UB sanitizer" OFF)
option(BUILD_EXAMPLES "Build example projects" ON)
option(BUILD_BENCHMARKS "Build benchmarks" OFF)
option(PACKAGE_DEB "Build .deb instalation packages" OFF)
option(PACKAGE_RPM "Build .rpm instalation packages" OFF)
option(PACKAGE_TGZ "Build .tgz package archive" ON)
option(PACKAGE_ZIP "Build .zip package archive" ON)
option(ENABLE_PPA "Enable PPA package build" OFF)
option(UPLOAD_PPA "Upload debian packages to the launchpad ppa repository" OFF)
set(PPA_DEBIAN_VERSION "ppa1" CACHE STRING "PPA version suffix for debian packages")
set(PROJECT_PPA_DISTRIB_TARGET "focal;bionic;xenial" CACHE STRING "Ubuntu PPA distrubutive names")

if(POLICY CMP0042)
  cmake_policy(SET CMP0042 NEW)
endif(POLICY CMP0042)

include(GNUInstallDirs)
include(ProjectUtils)

macro_ensure_out_of_source_build(
    "${CMAKE_PROJECT_NAME} requires an out of source build."
)

if(BUILD_TESTS)
    include(CTest)
    find_package(CUnit REQUIRED)
endif(BUILD_TESTS)

if(UPLOAD_PPA)
    set(ENABLE_PPA ON)
endif(UPLOAD_PPA)

# add a target to generate API documentation with Doxygen
find_package(Doxygen)
option(BUILD_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" OFF)

if(BUILD_DOCUMENTATION)
    if(NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif()
    set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
    set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    configure_file(${doxyfile_in} ${doxyfile} @ONLY)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
    install(CODE "execute_process(COMMAND ${CMAKE_BUILD_TOOL} docs)")
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
endif()

add_subdirectory(man)

if(NOT ENABLE_PPA)
    add_subdirectory(src)
else()
    set(PACKAGE_DEB ON)
endif()

set(CPACK_GENERATORS)
if(PACKAGE_TGZ)
    list(APPEND CPACK_GENERATORS "TGZ")
endif()
if(PACKAGE_ZIP)
    list(APPEND CPACK_GENERATORS "ZIP")
endif()
if(PACKAGE_DEB)
    list(APPEND CPACK_GENERATORS "DEB")
endif()
if(PACKAGE_RPM)
    list(APPEND CPACK_GENERATORS "RPM")
endif()

if(CPACK_GENERATORS)
    set(CPACK_GENERATOR "${CPACK_GENERATORS}")
    set(CPACK_SOURCE_IGNORE_FILES
            "/mxe/"
            "/\\\\.vscode/"
            "/\\\\.codelite/"
            "/\\\\.idea/"
            "/cmake-.*/"
            "\\\\.sh$"
            "\\\\.project$"
            "\\\\.workspace$"
            "\\\\.iml$"
            "\\\\.mk$"
            "\\\\.editorconfig$"
            "\\\\.astylerc$"
            "uncrustify\\\\.cfg$"
            "/Makefile$"
    )
    set(PROJECT_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
    add_subdirectory(installer)
endif(CPACK_GENERATORS)

message("${PROJECT_NAME} CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message("${PROJECT_NAME} CPACK_GENERATORS: ${CPACK_GENERATORS}")
message("${PROJECT_NAME} CMAKE_GENERATOR: ${CMAKE_GENERATOR}")
if (MXE_HOME)
	message("${PROJECT_NAME} MXE_HOME: ${MXE_HOME}")
endif()
if(CMAKE_SYSTEM_NAME)
    message("${PROJECT_NAME} CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
endif()
message("${PROJECT_NAME} CPU: ${CMAKE_SYSTEM_PROCESSOR}")
if(CMAKE_SIZEOF_VOID_P)
    message("${PROJECT_NAME} SIZEOF *VOID: ${CMAKE_SIZEOF_VOID_P}")
endif()
message("${PROJECT_NAME} PROJECT: ${CHANGELOG_LAST_LINE}")
if(CHANGELOG_MESSAGE)
    message("${PROJECT_NAME} CHANGELOG_MESSAGE:\n  ${CHANGELOG_MESSAGE}")
endif()
