# Find the CUnit headers and libraries
#
# CUNIT_INCLUDE_DIRS - The CUnit include directory (directory where
# CUnit/CUnit.h was found) CUNIT_LIBRARIES    - The libraries needed to use
# CUnit CUNIT_FOUND        - True if CUnit found in system

find_path(CUNIT_INCLUDE_DIR NAMES CUnit/CUnit.h)
mark_as_advanced(CUNIT_INCLUDE_DIR)

find_library(CUNIT_LIBRARY NAMES cunit libcunit cunitlib)
mark_as_advanced(CUNIT_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CUnit DEFAULT_MSG CUNIT_LIBRARY
                                  CUNIT_INCLUDE_DIR)

if(CUNIT_FOUND)
  set(CUNIT_LIBRARIES ${CUNIT_LIBRARY})
  set(CUNIT_INCLUDE_DIRS ${CUNIT_INCLUDE_DIR})
endif(CUNIT_FOUND)
