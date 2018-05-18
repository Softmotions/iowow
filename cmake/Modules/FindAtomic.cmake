# - Try to find libatomic
# ATOMIC_FOUND - System has ATOMIC
# ATOMIC_LIBRARY
include(FindPackageHandleStandardArgs)
find_library(ATOMIC_LIBRARY NAMES atomic atomic.so.1 libatomic.so.1)
find_package_handle_standard_args(atomic DEFAULT_MSG ATOMIC_LIBRARY)
mark_as_advanced(ATOMIC_LIBRARY)
