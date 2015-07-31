link_libraries(iowow_s ${CUNIT_LIBRARIES})
include_directories(${CUNIT_INCLUDE_DIRS})

set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TEST_DATA_DIR})

add_executable(iwfs_test1 iwfs_test1.c)
set_target_properties(iwfs_test1 PROPERTIES 
                      COMPILE_FLAGS "-DIW_STATIC")
add_test(NAME iwfs_test1 WORKING_DIRECTORY ${TEST_DATA_DIR} 
		 COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:iwfs_test1>)
