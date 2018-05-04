if (WIN32)      
  list(APPEND ALL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/platform/win32/mman/mman.c)
  set(ALL_SRC "${ALL_SRC}" PARENT_SCOPE)
endif(WIN32)
