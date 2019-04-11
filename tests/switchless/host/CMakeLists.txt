# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#oeedl_file(${switchless_SOURCE_DIR}/switchless.edl host gen)

add_executable(switchless_host #CXX SOURCES
    host.cpp
    switchless_u.c
#    ${gen}
    )

target_include_directories(switchless_host PRIVATE
#    ${CMAKE_CURRENT_SOURCE_DIR}/../shared
    ${switchless_SOURCE_DIR}/shared
#    ${CMAKE_CURRENT_BINARY_DIR}
#    ${CMAKE_CURRENT_SOURCE_DIR}
    )

target_link_libraries(switchless_host oehostapp switchless_shared_lib)
