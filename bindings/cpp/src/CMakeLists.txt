set(CHECKS_HEADERS
    ${PROJECT_SOURCE_DIR}/include/cppchecks/check.h
    ${PROJECT_SOURCE_DIR}/include/cppchecks/item.h
    ${PROJECT_SOURCE_DIR}/include/cppchecks/items.h
    ${PROJECT_SOURCE_DIR}/include/cppchecks/result.h
    ${PROJECT_SOURCE_DIR}/include/cppchecks/runner.h
    ${PROJECT_SOURCE_DIR}/include/cppchecks/status.h
)

add_library(${CMAKE_PROJECT_NAME}
    check.cpp
    item.cpp
    items.cpp
    result.cpp
    runner.cpp
    status.cpp
    ${CHECKS_HEADERS}
)

set(CCHECKS_SOURCE_DIR ${PROJECT_SOURCE_DIR}/../c)
add_subdirectory(${PROJECT_SOURCE_DIR}/../c ${CMAKE_BINARY_DIR}/cchecks)

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/../c/include
)

target_link_libraries(${CMAKE_PROJECT_NAME} cchecks)
