set(TESTS
    test_check
    test_item
    test_items
    test_result
    test_runner
    test_status
)
set(TEST_HEADERS
    item_impl.h
)

if (BUILD_WITH_CHECK_COVERAGE)
    SET(CMAKE_CXX_FLAGS "-g -O0 -Wall -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS "-fprofile-arcs -ftest-coverage")
endif()

foreach(TEST ${TESTS})
    add_executable(${TEST} ${TEST}.cpp
        ${TEST_HEADERS}
    )
    target_include_directories(${TEST} PRIVATE
        "${PROJECT_SOURCE_DIR}/tests"
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/googletest/googletest/include"
    )
    target_link_libraries(${TEST}
        PUBLIC
        gtest_main
        cppchecks
    )
    add_test(NAME ${TEST} COMMAND ${TEST})
endforeach()
