include_directories(${CUNIT_INCLUDE_DIRS})
find_package(OpenMP)

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
                    )
    add_executable(${TN} ${TN}.c)
    target_link_libraries(${TN} iowow_s ${CUNIT_LIBRARIES})
    set_target_properties(${TN} PROPERTIES
                          COMPILE_FLAGS "-DIW_STATIC")
    add_test(NAME ${TN} WORKING_DIRECTORY ${TEST_DATA_DIR}
             COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:${TN}>)
endforeach()

if (NOT WIN32 AND OpenMP_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
  add_executable(iwkv_test6 iwkv_test6.c)
  target_link_libraries(iwkv_test6 iowow_s ${CUNIT_LIBRARIES})
  set_target_properties(iwkv_test6 PROPERTIES
                        COMPILE_FLAGS "-DIW_STATIC")
  add_test(NAME iwkv_test6 WORKING_DIRECTORY ${TEST_DATA_DIR}
           COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:iwkv_test6>)
endif()

