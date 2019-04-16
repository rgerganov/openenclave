# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set (CRYPTO_SRC
    ../common/asn1.c
    asn1.c
    cert.c
    crl.c
    ec.c
    cmac.c
    hmac.c
    key.c
    random.c
    rsa.c
    sha.c)

if (OE_SGX)
    set(PLATFORM_SRC
        ../common/sgx/qeidentity.c
        ../common/sgx/quote.c
        ../common/sgx/report.c
        ../common/sgx/revocation.c
        ../common/sgx/sgxcertextensions.c
        ../common/sgx/tcbinfo.c
        sgx/link.c
        sgx/qeidinfo.c
        sgx/report.c
        sgx/revocationinfo.c
        sgx/start.S)
elseif(OE_TRUSTZONE)
    message("TODO: ADD ARM files.")
endif()

add_library(oecrypto STATIC ${CRYPTO_SRC})
add_library(oeenclave STATIC
    ../common/datetime.c
    ../common/cert.c
    ../common/kdf.c
    asym_keys.c
    ${PLATFORM_SRC})

maybe_build_using_clangw(oecrypto)
maybe_build_using_clangw(oeenclave)


if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oecrypto PRIVATE -Wjump-misses-init)
target_compile_options(oeenclave PRIVATE -Wjump-misses-init)
endif()

target_include_directories(oecrypto PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)
target_include_directories(oeenclave PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oecrypto PUBLIC
    oe_includes
    mbedcrypto)

target_link_libraries(oeenclave PUBLIC oecrypto)

set_property(TARGET oecrypto PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oecrypto EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
install(TARGETS oeenclave EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
