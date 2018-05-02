check_library_exists(pthread pthread_condattr_setclock "" HAVE_PTHREAD_CONDATTR_SETCLOCK)
if (HAVE_PTHREAD_CONDATTR_SETCLOCK)
  set_source_files_properties(iwal.c PROPERTIES COMPILE_FLAGS -DIW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
endif()
