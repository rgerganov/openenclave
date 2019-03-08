# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# OS-specific source files
if (UNIX)
  set(PLATFORM_SRC
    ../../../common/sgx/rand.S)
elseif (WIN32)
  set(PLATFORM_SRC
    ../../../common/sgx/rand.asm)
else()
  message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif()

add_executable(hostcrypto
    ${PLATFORM_SRC}
    main.c
    ../read_file.c
    ../asn1_tests.c
    ../crl_tests.c
    ../ec_tests.c
    ../hash.c
    ../hmac_tests.c
    ../kdf_tests.c
    ../random_tests.c
    ../rdrand_test.c
    ../rsa_tests.c
    ../sha_tests.c
    ../tests.c
    ../utils.c)

target_link_libraries(hostcrypto oehost)
add_test(tests/crypto/host hostcrypto)
