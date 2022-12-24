set(TESTS
    test_check
    test_item
    test_result
    test_runner
    test_status
)

foreach(TEST ${TESTS})
    add_executable(${TEST} ${TEST}.c)
    target_include_directories(${TEST} PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/cmocka/include"
    )
    target_link_libraries(${TEST}
        PUBLIC
        cmocka
        cchecks
    )
    add_test(NAME ${TEST} COMMAND ${TEST})
endforeach()
