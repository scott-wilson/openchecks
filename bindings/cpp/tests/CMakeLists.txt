set(TESTS
    test_check
    test_item
    test_result
    test_runner
    test_status
)
set(TEST_HEADERS
    item_impl.h
)

foreach(TEST ${TESTS})
    add_executable(${TEST} ${TEST}.cpp
        ${TEST_HEADERS}
    )
    target_include_directories(${TEST} PRIVATE
    "${PROJECT_SOURCE_DIR}/tests"
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/../c/include"
        "${PROJECT_SOURCE_DIR}/googletest/googlemock/include"
        "${PROJECT_SOURCE_DIR}/googletest/googletest/include"
    )
    target_link_libraries(${TEST}
        PUBLIC
        gtest
        gtest_main
        cchecks
        cppchecks
    )
    add_test(NAME ${TEST} COMMAND ${TEST})
endforeach()
