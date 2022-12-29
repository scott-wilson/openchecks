cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

set(CCHECKS_VERSION_MAJOR "0")
set(CCHECKS_VERSION_MINOR "1")
set(CCHECKS_VERSION_PATCH "0")
set(CCHECKS_VERSION ${CCHECKS_VERSION_MAJOR}.${CCHECKS_VERSION_MINOR}.${CCHECKS_VERSION_PATCH})

project(cchecks VERSION ${CCHECKS_VERSION} LANGUAGES C)

# --------------------------------------------------------------------------------
# Build Options
# --------------------------------------------------------------------------------
set(BUILD_SHARED_LIBS OFF) # build cmocka as a static lib

# --------------------------------------------------------------------------------
# Do the build
# --------------------------------------------------------------------------------
set(UNIT_TESTING OFF)

enable_testing()

add_subdirectory(corrosion)
corrosion_import_crate(MANIFEST_PATH "${CMAKE_SOURCE_DIR}/Cargo.toml")

add_subdirectory(cmocka)
add_subdirectory(tests)
