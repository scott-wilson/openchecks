set(TESTS
    test_item
    test_items
    test_result
    test_runner
    test_status
)
set(TEST_HEADERS
    check_impl.h
    item_impl.h
    items_impl.h
    result_impl.h
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
    target_compile_options(${TEST} PRIVATE -Werror -Wall)
    add_test(NAME ${TEST} COMMAND ${TEST})
endforeach()
