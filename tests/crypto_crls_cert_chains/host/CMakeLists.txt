# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../common/crypto_crls_cert_chains.edl host gen)

add_executable(crypto-extra_host host.cpp ${gen})
target_include_directories(crypto-extra_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(crypto-extra_host oehostapp)
