include_directories(${CUNIT_INCLUDE_DIRS})

set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TEST_DATA_DIR})

file(GLOB datafiles RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.ref")
foreach(file ${datafiles})
  configure_file("${file}" "${file}" COPYONLY)
endforeach()

foreach(TN IN ITEMS iwkv_test1
                    iwkv_test2
                    iwkv_test3
                    iwkv_test4
                    iwkv_test5
                    iwkv_test6
                    iwkv_test7
                    iwkv_test8
                    )
    add_executable(${TN} ${TN}.c)
    target_link_libraries(${TN} iowow_s ${CUNIT_LIBRARIES})
    set_target_properties(${TN} PROPERTIES
                          COMPILE_FLAGS "-DIW_STATIC")
    add_test(NAME ${TN} WORKING_DIRECTORY ${TEST_DATA_DIR}
             COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:${TN}>)
endforeach()


