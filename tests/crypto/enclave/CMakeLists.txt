# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

add_subdirectory(host)
add_test(tests/crypto/enclave host/cryptohost ./enc/cryptoenc)
