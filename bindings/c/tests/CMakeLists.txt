set(TESTS
    test_check
    test_item
    test_result
    test_runner
    test_status
)

if (BUILD_WITH_CHECK_COVERAGE)
    SET(CMAKE_CXX_FLAGS "-g -O0 -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS "-g -O0 -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS "-fprofile-arcs -ftest-coverage")
endif()

if(CODE_COVERAGE AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # Don't use e.g. GNU extension (like -std=gnu++11) for portability
    set(CMAKE_C_EXTENSIONS OFF)

    # Code Coverage Configuration
    add_library(coverage_config INTERFACE)

    # Add required flags (GCC & LLVM/Clang)
    target_compile_options(coverage_config INTERFACE
        -O0        # no optimization
        -g         # generate debug info
        --coverage # sets all required flags
    )
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
        target_link_options(coverage_config INTERFACE --coverage)
    else()
        target_link_libraries(coverage_config INTERFACE --coverage)
    endif()
endif(CODE_COVERAGE AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")

foreach(TEST ${TESTS})
    add_executable(${TEST} ${TEST}.c)
    target_include_directories(${TEST} PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/cmocka/include"
        "${PROJECT_SOURCE_DIR}/tests/common"
    )
    target_link_libraries(${TEST}
        PUBLIC
        cmocka
        cchecks
    )

    if (MSVC)
        target_compile_options(${TEST} PRIVATE -WX -Wall)
    else()
        target_compile_options(${TEST} PRIVATE -Werror -Wall)
    endif()

    add_test(NAME ${TEST} COMMAND ${TEST})
endforeach()
