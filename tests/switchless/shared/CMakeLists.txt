# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(switchless_shared_lib lockless_queue.c thread_control.c)

target_include_directories(switchless_shared_lib PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )
