cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

set(FUZZ_TARGETS
result_new_failed
result_new_passed
result_new_skipped
result_new_warning
result_new
runner_run
status_has_failed
status_has_passed
status_is_pending
)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)

project(cchecks_fuzz)

link_directories("${PROJECT_SOURCE_DIR}/../build")

foreach(FUZZ_TARGET ${FUZZ_TARGETS})
    add_executable(${FUZZ_TARGET} ${FUZZ_TARGET}.cpp)
    target_compile_options(${FUZZ_TARGET} PRIVATE $<$<C_COMPILER_ID:Clang>:-g -fsanitize=fuzzer>)
    target_include_directories(${FUZZ_TARGET} PRIVATE
        "${PROJECT_SOURCE_DIR}/../include"
    )

    if (MSVC)
        add_definitions(-D_CRT_SECURE_NO_WARNINGS)
        target_compile_options(${FUZZ_TARGET} PRIVATE -WX -W4)
    else()
        target_compile_options(${FUZZ_TARGET} PRIVATE -Werror -Wall)
    endif()

    target_link_libraries(${FUZZ_TARGET}
        PUBLIC
        cchecks
        PRIVATE $<$<C_COMPILER_ID:Clang>:-fsanitize=fuzzer>
    )
endforeach(FUZZ_TARGET ${FUZZ_TARGETS})
