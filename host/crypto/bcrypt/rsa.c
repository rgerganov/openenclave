// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../rsa.h"
#include "bcrypt.h"
#include "key.h"

#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/utils.h>

/*
 * Magic numbers for the RSA key implementation structures. These values
 * were copied from the linux rsa.c file. These can be consolidated once
 * more crypto code is ported to Windows.
 */
static const uint64_t _PRIVATE_KEY_MAGIC = 0x7bf635929a714b2c;
static const uint64_t _PUBLIC_KEY_MAGIC = 0x8f8f72170025426d;

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));

static const oe_bcrypt_read_key_args_t _PRIVATE_RSA_KEY_ARGS = {
    CNG_RSA_PRIVATE_KEY_BLOB,
    BCRYPT_RSA_ALG_HANDLE,
    BCRYPT_RSAPRIVATE_BLOB};

// static const oe_bcrypt_read_key_args_t _PUBLIC_RSA_KEY_ARGS = {
//    CNG_RSA_PUBLIC_KEY_BLOB,
//    BCRYPT_RSA_ALG_HANDLE,
//    BCRYPT_RSAPUBLIC_BLOB};

static oe_result_t _get_public_rsa_blob_info(
    BCRYPT_KEY_HANDLE key,
    uint8_t** buffer,
    ULONG* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    NTSTATUS status;
    uint8_t* buffer_local = NULL;
    ULONG buffer_local_size = 0;
    BCRYPT_RSAKEY_BLOB* key_header;

    if (!key || !buffer || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    status = BCryptExportKey(
        key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &buffer_local_size, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    buffer_local = (uint8_t*)malloc(buffer_local_size);
    if (buffer_local == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    status = BCryptExportKey(
        key,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        buffer_local,
        buffer_local_size,
        &buffer_local_size,
        0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Sanity check to ensure we get modulus and public exponent. */
    key_header = (BCRYPT_RSAKEY_BLOB*)buffer_local;
    if (key_header->cbPublicExp == 0 || key_header->cbModulus == 0)
        OE_RAISE(OE_FAILURE);

    *buffer = buffer_local;
    *buffer_size = buffer_local_size;
    buffer_local = NULL;
    result = OE_OK;

done:
    if (buffer_local)
    {
        oe_secure_zero_fill(buffer_local, buffer_local_size);
        free(buffer_local);
        buffer_local_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_bcrypt_read_key_pem(
        pem_data,
        pem_size,
        private_key,
        _PRIVATE_RSA_KEY_ARGS,
        _PRIVATE_KEY_MAGIC);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return OE_UNSUPPORTED;
    //    return oe_private_key_write_pem(
    //        (const oe_private_key_t*)private_key,
    //        pem_data,
    //        pem_size,
    //        _private_key_write_pem_callback,
    //        _PRIVATE_KEY_MAGIC);
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return OE_UNSUPPORTED;
    //    return oe_public_key_read_pem(
    //        pem_data,
    //        pem_size,
    //        (oe_public_key_t*)public_key,
    //        EVP_PKEY_RSA,
    //        _PUBLIC_KEY_MAGIC);
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return OE_UNSUPPORTED;
    //    return oe_public_key_write_pem(
    //        (const oe_public_key_t*)private_key,
    //        pem_data,
    //        pem_size,
    //        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key)
{
    return oe_bcrypt_key_free(private_key, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key)
{
    return oe_bcrypt_key_free(public_key, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_private_key_t* impl = (const oe_private_key_t*)private_key;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, _PRIVATE_KEY_MAGIC) || !hash_data ||
        !hash_size || hash_size > MAXDWORD || !signature_size ||
        *signature_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        ULONG sig_size;
        NTSTATUS status;
        BCRYPT_PKCS1_PADDING_INFO info;
        uint8_t hash_data_copy[64];

        /* Check for support hash types and correct sizes. */
        switch (hash_type)
        {
            case OE_HASH_TYPE_SHA256:
                if (hash_size != 32)
                    OE_RAISE(OE_INVALID_PARAMETER);
                info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
                break;
            case OE_HASH_TYPE_SHA512:
                if (hash_size != 64)
                    OE_RAISE(OE_INVALID_PARAMETER);
                info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
                break;
            default:
                OE_RAISE(OE_INVALID_PARAMETER);
        }

        /* Need to make a copy since BCryptSignHash's pbInput isn't const. */
        OE_CHECK(oe_memcpy_s(
            hash_data_copy, sizeof(hash_data_copy), hash_data, hash_size));

        /* Determine the size of the signature; fail if buffer is too small */
        status = BCryptSignHash(
            impl->pkey,
            &info,
            hash_data_copy,
            (ULONG)hash_size,
            NULL,
            0,
            &sig_size,
            BCRYPT_PAD_PKCS1);

        if (sig_size > *signature_size)
        {
            *signature_size = sig_size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /*
         * Perform the signing now. Note that we use the less secure PKCS1
         * signature padding because Intel requires it. However, this is
         * fine since there are no known attacks on PKCS1 signature
         * verification.
         */
        status = BCryptSignHash(
            impl->pkey,
            &info,
            hash_data_copy,
            (ULONG)hash_size,
            signature,
            sig_size,
            &sig_size,
            BCRYPT_PAD_PKCS1);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE(OE_CRYPTO_ERROR);

        *signature_size = sig_size;
    }

    result = OE_OK;

done:
    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    return OE_UNSUPPORTED;
    //    return oe_public_key_verify(
    //        (oe_public_key_t*)public_key,
    //        hash_type,
    //        hash_data,
    //        hash_size,
    //        signature,
    //        signature_size,
    //        _PUBLIC_KEY_MAGIC);
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_generate_key_pair(
    uint64_t bits,
    uint64_t exponent,
    oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    return OE_UNSUPPORTED;
    //    return _generate_key_pair(
    //        bits,
    //        exponent,
    //        (oe_private_key_t*)private_key,
    //        (oe_public_key_t*)public_key);
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    uint8_t* keybuf = NULL;
    ULONG keybuf_size;
    BCRYPT_RSAKEY_BLOB* keyblob;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, _PUBLIC_KEY_MAGIC) || !buffer_size ||
        *buffer_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If buffer is null, then buffer_size must be zero */
    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_public_rsa_blob_info(impl->pkey, &keybuf, &keybuf_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)keybuf;
    if (keyblob->cbModulus > *buffer_size)
    {
        *buffer_size = keyblob->cbModulus;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        buffer,
        *buffer_size,
        keybuf + sizeof(*keyblob) + keyblob->cbPublicExp,
        keyblob->cbModulus));

    *buffer_size = keyblob->cbModulus;
    result = OE_OK;

done:
    if (keybuf)
    {
        oe_secure_zero_fill(keybuf, keybuf_size);
        free(keybuf);
        keybuf_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    uint8_t* keybuf = NULL;
    ULONG keybuf_size;
    BCRYPT_RSAKEY_BLOB* keyblob;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, _PUBLIC_KEY_MAGIC) || !buffer_size ||
        *buffer_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If buffer is null, then buffer_size must be zero */
    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_public_rsa_blob_info(impl->pkey, &keybuf, &keybuf_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)keybuf;
    if (keyblob->cbPublicExp > *buffer_size)
    {
        *buffer_size = keyblob->cbPublicExp;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        buffer, *buffer_size, keybuf + sizeof(*keyblob), keyblob->cbPublicExp));

    *buffer_size = keyblob->cbPublicExp;
    result = OE_OK;

done:
    if (keybuf)
    {
        oe_secure_zero_fill(keybuf, keybuf_size);
        free(keybuf);
        keybuf_size = 0;
    }

    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* public_key1,
    const oe_rsa_public_key_t* public_key2,
    bool* equal)
{
    return OE_UNSUPPORTED;
    // return _public_key_equal(
    //    (oe_public_key_t*)public_key1, (oe_public_key_t*)public_key2, equal);
}

oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* impl = (oe_private_key_t*)private_key;
    uint8_t* keybuf = NULL;
    ULONG keybuf_size;

    if (!oe_bcrypt_key_is_valid(impl, _PRIVATE_KEY_MAGIC) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_public_rsa_blob_info(impl->pkey, &keybuf, &keybuf_size));

    /*
     * Export the key blob to a public key. Note that the private key blob has
     * the modulus and the exponent already, so we can just use it to import
     * the public key.
     */
    {
        NTSTATUS status;
        BCRYPT_KEY_HANDLE public_key_handle;

        status = BCryptImportKeyPair(
            BCRYPT_RSA_ALG_HANDLE,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            &public_key_handle,
            keybuf,
            keybuf_size,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE(OE_CRYPTO_ERROR);

        ((oe_public_key_t*)public_key)->magic = _PUBLIC_KEY_MAGIC;
        ((oe_public_key_t*)public_key)->pkey = public_key_handle;
    }

    result = OE_OK;

done:
    if (keybuf)
    {
        oe_secure_zero_fill(keybuf, keybuf_size);
        free(keybuf);
        keybuf_size = 0;
    }

    return result;
}
