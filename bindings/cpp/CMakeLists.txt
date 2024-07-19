cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

set(CPPOPENCHECKS_VERSION_MAJOR "0")
set(CPPOPENCHECKS_VERSION_MINOR "1")
set(CPPOPENCHECKS_VERSION_PATCH "0")
set(CPPOPENCHECKS_VERSION ${CPPOPENCHECKS_VERSION_MAJOR}.${CPPOPENCHECKS_VERSION_MINOR}.${CPPOPENCHECKS_VERSION_PATCH})

project(cppopenchecks VERSION ${CPPOPENCHECKS_VERSION} LANGUAGES CXX)

# --------------------------------------------------------------------------------
# Build Options
# --------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------------------
# Do the build
# --------------------------------------------------------------------------------
set(CHECKS_HEADERS
    ${PROJECT_SOURCE_DIR}/include/openchecks/check.h
    ${PROJECT_SOURCE_DIR}/include/openchecks/core.h
    ${PROJECT_SOURCE_DIR}/include/openchecks/item.h
    ${PROJECT_SOURCE_DIR}/include/openchecks/items.h
    ${PROJECT_SOURCE_DIR}/include/openchecks/result.h
    ${PROJECT_SOURCE_DIR}/include/openchecks/runner.h
    ${PROJECT_SOURCE_DIR}/include/openchecks/status.h
)
set(CHECKS_SRC
    ${PROJECT_SOURCE_DIR}/src/core.cpp
)

add_library(${CMAKE_PROJECT_NAME}
    ${CHECKS_HEADERS}
    ${CHECKS_SRC}
)

set(COPENCHECKS_SOURCE_DIR ${PROJECT_SOURCE_DIR}/../c)
add_subdirectory(${PROJECT_SOURCE_DIR}/../c ${CMAKE_BINARY_DIR}/copenchecks)

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/../c/include
)
message("TEST ${CMAKE_PROJECT_NAME} ${PROJECT_SOURCE_DIR} ${INCLUDE_DIRECTORIES}")

set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(${CMAKE_PROJECT_NAME} copenchecks)

install(FILES ${CHECKS_HEADERS} DESTINATION include/openchecks)
install(TARGETS ${CMAKE_PROJECT_NAME} EXPORT cppopenchecks DESTINATION lib)

if (BUILD_CPPOPENCHECKS_TESTS)
    enable_testing()
    add_subdirectory(googletest EXCLUDE_FROM_ALL)
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(tests)
endif()
