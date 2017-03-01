cmake_minimum_required(VERSION 2.6)
#cmake_policy(VERSION 2.6)


set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")
include(CMakeToolsHelpers OPTIONAL)
set(DEB_CHANGELOG_REQUIRED ON)
set(DEB_CHANGELOG "${CMAKE_CURRENT_SOURCE_DIR}/Changelog")
include(DebChangelog)

set(PROJECT_NAME "ejdb2")
set(PROJECT_VENDOR "Softmotions (http://softmotions.com)")
set(PROJECT_WEBSITE "https://github.com/Softmotions/iowow")
set(PROJECT_MAINTAINER "Anton Adamansky <adamansky@softmotions.com>")
set(PROJECT_DESCRIPTION_SUMMARY "File system IO library")
set(PROJECT_DESCRIPTION "File system IO library")
set(CHANGELOG_MESSAGE ${CHANGELOG_LAST_MESSAGE})
set(PROJECT_PPA "ppa:adamansky/ejdb2")
set(PROJECT_PPA_USER "adamansky")
set(PROJECT_PPA_DISTRIB_TARGET xenial)

project(${PROJECT_NAME} C)

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
#option(BUILD_SAMPLES "Build iowow sample projects" OFF)
option(PACKAGE_DEB "Build .deb instalation packages" OFF)
option(PACKAGE_TGZ "Build .tgz package archive" ON)
option(PACKAGE_ZIP "Build .zip package archive" ON)
option(ENABLE_PPA "Enable PPA package build" OFF)
option(UPLOAD_PPA "Upload debian packages to the launchpad ppa repository" OFF)
option(PPA_DEBIAN_VERSION "PPA version suffix for debian packages" "ppa1")
option("PROJECT_PPA_DISTRIB_TARGET" "Ubuntu PPA distrubutive names" "xenial;")

if(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
endif(POLICY CMP0042)

if(CMAKE_SIZEOF_VOID_P MATCHES 8)
        set(PROJECT_ARCH "x86_64")
else(CMAKE_SIZEOF_VOID_P MATCHES 8)
        set(PROJECT_ARCH "x86")
endif(CMAKE_SIZEOF_VOID_P MATCHES 8)

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
option(BUILD_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})

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

if(CPACK_GENERATORS)
    set(CPACK_GENERATOR "${CPACK_GENERATORS}")
    set(CPACK_SOURCE_IGNORE_FILES
            "iowow\\\\.mk$"
            "\\\\.project$"
            "\\\\.workspace$"
            "\\\\.iml$"
            "\\\\.cmake_dirty$"
            "ctest\\\\.cmake"
            "compile_commands\\\\.json$"
            "/Makefile$"
    )
    add_subdirectory(installer)
endif(CPACK_GENERATORS)

message("${PROJECT_NAME} CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message("${PROJECT_NAME} CPACK_GENERATORS: ${CPACK_GENERATORS}")

if(CMAKE_SYSTEM_NAME)
    message("${PROJECT_NAME} CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
endif()
if(PROJECT_ARCH)
    message("${PROJECT_NAME} PROJECT_ARCH: ${PROJECT_ARCH}")
endif()
message("${PROJECT_NAME} PROJECT: ${CHANGELOG_LAST_LINE}")
if(CHANGELOG_MESSAGE)
    message("${PROJECT_NAME} CHANGELOG_MESSAGE:\n  ${CHANGELOG_MESSAGE}")
endif()
