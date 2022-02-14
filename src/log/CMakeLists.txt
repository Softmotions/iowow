check_symbol_exists(basename_r libgen.h HAVE_BASENAME_R)
if (HAVE_BASENAME_R)
  set_source_files_properties(iwlog.c PROPERTIES COMPILE_FLAGS -DIW_HAVE_BASENAME_R)
endif()
