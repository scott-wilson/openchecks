cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

set(CPPCHECKS_VERSION_MAJOR "0")
set(CPPCHECKS_VERSION_MINOR "1")
set(CPPCHECKS_VERSION_PATCH "0")
set(CPPCHECKS_VERSION ${CPPCHECKS_VERSION_MAJOR}.${CPPCHECKS_VERSION_MINOR}.${CPPCHECKS_VERSION_PATCH})

project(cppchecks VERSION ${CPPCHECKS_VERSION} LANGUAGES CXX)

# --------------------------------------------------------------------------------
# Build Options
# --------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------------------
# Do the build
# --------------------------------------------------------------------------------
add_subdirectory(src)

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(googletest)
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(tests)
endif()
