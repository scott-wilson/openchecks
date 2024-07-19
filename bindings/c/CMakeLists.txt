cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

set(COPENCHECKS_VERSION_MAJOR "0")
set(COPENCHECKS_VERSION_MINOR "1")
set(COPENCHECKS_VERSION_PATCH "0")
set(COPENCHECKS_VERSION ${COPENCHECKS_VERSION_MAJOR}.${COPENCHECKS_VERSION_MINOR}.${COPENCHECKS_VERSION_PATCH})

project(copenchecks VERSION ${COPENCHECKS_VERSION} LANGUAGES C)

# --------------------------------------------------------------------------------
# Build Options
# --------------------------------------------------------------------------------
option(CODE_COVERAGE "Enable coverage reporting" OFF)

# --------------------------------------------------------------------------------
# Do the build
# --------------------------------------------------------------------------------
set(UNIT_TESTING OFF)

add_subdirectory(corrosion)

if (NOT DEFINED COPENCHECKS_SOURCE_DIR OR COPENCHECKS_SOURCE_DIR MATCHES "")
set(COPENCHECKS_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
endif()

corrosion_import_crate(MANIFEST_PATH "${COPENCHECKS_SOURCE_DIR}/Cargo.toml")

if (BUILD_COPENCHECKS_TESTS)
    enable_testing()
    add_subdirectory(cmocka)
    add_subdirectory(tests)
endif()
