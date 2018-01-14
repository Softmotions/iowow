link_libraries(iowow_s ${CUNIT_LIBRARIES})
include_directories(${CUNIT_INCLUDE_DIRS})

set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TEST_DATA_DIR})

configure_file(iwkv_test1_1.ref iwkv_test1_1.ref COPYONLY)
configure_file(iwkv_test1_2.ref iwkv_test1_2.ref COPYONLY)
configure_file(iwkv_test1_3.ref iwkv_test1_3.ref COPYONLY)

foreach(TN IN ITEMS iwkv_test1
                    iwkv_test2
                    iwkv_test3)
    add_executable(${TN} ${TN}.c)
    set_target_properties(${TN} PROPERTIES
                          COMPILE_FLAGS "-DIW_STATIC")
    add_test(NAME ${TN} WORKING_DIRECTORY ${TEST_DATA_DIR}
             COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:${TN}>)
endforeach()
