// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//#include "ec.h"
#include <openenclave/bits/safecrt.h>
//#include <openenclave/internal/defs.h>
#include <openenclave/internal/ec.h>
//#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
//#include <openssl/obj_mac.h>
//#include <openssl/pem.h>
//#include <string.h>
//#include "init.h"
#include "bcrypt.h"
#include "key.h"

/* Magic numbers for the EC key implementation structures */
static const uint64_t _PRIVATE_KEY_MAGIC = 0x19a751419ae04bbc;
static const uint64_t _PUBLIC_KEY_MAGIC = 0xb1d39580c1f14c02;

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_ec_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_ec_private_key_t));

// static const oe_bcrypt_read_key_args_t _PRIVATE_EC_KEY_ARGS = {
//    X509_ECC_PRIVATE_KEY,
//    BCRYPT_ECDSA_P256_ALGORITHM,
//    BCRYPT_ECCPRIVATE_BLOB};

static const oe_bcrypt_read_key_args_t _PUBLIC_EC_KEY_ARGS = {
    szOID_ECC_PUBLIC_KEY,
    BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECCPUBLIC_BLOB};

static const DWORD OE_BCRYPT_UNSUPPORTED_EC_TYPE = 0;

static DWORD _get_bcrypt_magic(oe_ec_type_t ec_type)
{
    switch (ec_type)
    {
        /* Note that bcrypt magic is more specific than OpenSSL NID:
         * - Distinguishes between ECDSA/ECDH keys
         * - Distinguishes between public/private keys
         */
        case OE_EC_TYPE_SECP256R1:
            return BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        default:
            return OE_BCRYPT_UNSUPPORTED_EC_TYPE;
    }
}
// static int _get_nid(oe_ec_type_t ec_type)
//{
//    switch (ec_type)
//    {
//        case OE_EC_TYPE_SECP256R1:
//            return NID_X9_62_prime256v1;
//        default:
//            return NID_undef;
//    }
//}
//
// static oe_result_t _private_key_write_pem_callback(BIO* bio, EVP_PKEY* pkey)
//{
//    oe_result_t result = OE_UNEXPECTED;
//    EC_KEY* ec = NULL;
//
//    if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
//        OE_RAISE(OE_CRYPTO_ERROR);
//
//    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
//        OE_RAISE(OE_CRYPTO_ERROR);
//
//    result = OE_OK;
//
// done:
//
//    if (ec)
//        EC_KEY_free(ec);
//
//    return result;
//}
//
// static oe_result_t _generate_key_pair(
//    oe_ec_type_t ec_type,
//    oe_private_key_t* private_key,
//    oe_public_key_t* public_key)
//{
//    oe_result_t result = OE_UNEXPECTED;
//    int nid;
//    EC_KEY* ec_private = NULL;
//    EC_KEY* ec_public = NULL;
//    EVP_PKEY* pkey_private = NULL;
//    EVP_PKEY* pkey_public = NULL;
//    EC_POINT* point = NULL;
//
//    if (private_key)
//        oe_secure_zero_fill(private_key, sizeof(*private_key));
//
//    if (public_key)
//        oe_secure_zero_fill(public_key, sizeof(oe_public_key_t));
//
//    /* Check parameters */
//    if (!private_key || !public_key)
//        OE_RAISE(OE_INVALID_PARAMETER);
//
//    /* Initialize OpenSSL */
//    oe_initialize_openssl();
//
//    /* Get the NID for this curve type */
//    if ((nid = _get_nid(ec_type)) == NID_undef)
//        OE_RAISE(OE_FAILURE);
//
//    /* Create the private EC key */
//    {
//        /* Create the private key */
//        if (!(ec_private = EC_KEY_new_by_curve_name(nid)))
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Set the EC named-curve flag */
//        EC_KEY_set_asn1_flag(ec_private, OPENSSL_EC_NAMED_CURVE);
//
//        /* Generate the public/private key pair */
//        if (!EC_KEY_generate_key(ec_private))
//            OE_RAISE(OE_CRYPTO_ERROR);
//    }
//
//    /* Create the public EC key */
//    {
//        /* Create the public key */
//        if (!(ec_public = EC_KEY_new_by_curve_name(nid)))
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Set the EC named-curve flag */
//        EC_KEY_set_asn1_flag(ec_public, OPENSSL_EC_NAMED_CURVE);
//
//        /* Duplicate public key point from the private key */
//        if (!(point = EC_POINT_dup(
//                  EC_KEY_get0_public_key(ec_private),
//                  EC_KEY_get0_group(ec_public))))
//        {
//            OE_RAISE(OE_CRYPTO_ERROR);
//        }
//
//        /* Set the public key */
//        if (!EC_KEY_set_public_key(ec_public, point))
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Keep from being freed below */
//        point = NULL;
//    }
//
//    /* Create the PKEY private key wrapper */
//    {
//        /* Create the private key structure */
//        if (!(pkey_private = EVP_PKEY_new()))
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Initialize the private key from the generated key pair */
//        if (!EVP_PKEY_assign_EC_KEY(pkey_private, ec_private))
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Initialize the private key */
//        oe_private_key_init(private_key, pkey_private, _PRIVATE_KEY_MAGIC);
//
//        /* Keep these from being freed below */
//        ec_private = NULL;
//        pkey_private = NULL;
//    }
//
//    /* Create the PKEY public key wrapper */
//    {
//        /* Create the public key structure */
//        if (!(pkey_public = EVP_PKEY_new()))
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Initialize the public key from the generated key pair */
//        if (!EVP_PKEY_assign_EC_KEY(pkey_public, ec_public))
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Initialize the public key */
//        oe_public_key_init(public_key, pkey_public, _PUBLIC_KEY_MAGIC);
//
//        /* Keep these from being freed below */
//        ec_public = NULL;
//        pkey_public = NULL;
//    }
//
//    result = OE_OK;
//
// done:
//
//    if (ec_private)
//        EC_KEY_free(ec_private);
//
//    if (ec_public)
//        EC_KEY_free(ec_public);
//
//    if (pkey_private)
//        EVP_PKEY_free(pkey_private);
//
//    if (pkey_public)
//        EVP_PKEY_free(pkey_public);
//
//    if (point)
//        EC_POINT_free(point);
//
//    if (result != OE_OK)
//    {
//        oe_private_key_free(private_key, _PRIVATE_KEY_MAGIC);
//        oe_public_key_free(public_key, _PUBLIC_KEY_MAGIC);
//    }
//
//    return result;
//}
//
// static oe_result_t _public_key_equal(
//    const oe_public_key_t* public_key1,
//    const oe_public_key_t* public_key2,
//    bool* equal)
//{
//    oe_result_t result = OE_UNEXPECTED;
//    EC_KEY* ec1 = NULL;
//    EC_KEY* ec2 = NULL;
//
//    if (equal)
//        *equal = false;
//
//    /* Reject bad parameters */
//    if (!oe_public_key_is_valid(public_key1, _PUBLIC_KEY_MAGIC) ||
//        !oe_public_key_is_valid(public_key2, _PUBLIC_KEY_MAGIC) || !equal)
//        OE_RAISE(OE_INVALID_PARAMETER);
//
//    {
//        ec1 = EVP_PKEY_get1_EC_KEY(public_key1->pkey);
//        ec2 = EVP_PKEY_get1_EC_KEY(public_key2->pkey);
//        const EC_GROUP* group1 = EC_KEY_get0_group(ec1);
//        const EC_GROUP* group2 = EC_KEY_get0_group(ec2);
//        const EC_POINT* point1 = EC_KEY_get0_public_key(ec1);
//        const EC_POINT* point2 = EC_KEY_get0_public_key(ec2);
//
//        if (!ec1 || !ec2 || !group1 || !group2 || !point1 || !point2)
//            OE_RAISE(OE_CRYPTO_ERROR);
//
//        /* Compare group and public key point */
//        if (EC_GROUP_cmp(group1, group2, NULL) == 0 &&
//            EC_POINT_cmp(group1, point1, point2, NULL) == 0)
//        {
//            *equal = true;
//        }
//    }
//
//    result = OE_OK;
//
// done:
//
//    if (ec1)
//        EC_KEY_free(ec1);
//
//    if (ec2)
//        EC_KEY_free(ec2);
//
//    return result;
//}
//
// void oe_ec_public_key_init(oe_ec_public_key_t* public_key, EVP_PKEY* pkey)
//{
//    return oe_public_key_init(
//        (oe_public_key_t*)public_key, pkey, _PUBLIC_KEY_MAGIC);
//}
//
// void oe_ec_private_key_init(oe_ec_private_key_t* private_key, EVP_PKEY* pkey)
//{
//    return oe_private_key_init(
//        (oe_private_key_t*)private_key, pkey, _PRIVATE_KEY_MAGIC);
//}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return OE_UNSUPPORTED;
    // return oe_private_key_read_pem(
    //    pem_data,
    //    pem_size,
    //    (oe_private_key_t*)private_key,
    //    EVP_PKEY_EC,
    //    _PRIVATE_KEY_MAGIC);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return OE_UNSUPPORTED;
    // return oe_private_key_write_pem(
    //    (const oe_private_key_t*)private_key,
    //    pem_data,
    //    pem_size,
    //    _private_key_write_pem_callback,
    //    _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_read_pem(
    oe_ec_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_bcrypt_read_key_pem(
        pem_data, pem_size, public_key, _PUBLIC_EC_KEY_ARGS, _PUBLIC_KEY_MAGIC);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return OE_UNSUPPORTED;
    // return oe_public_key_write_pem(
    //    (const oe_public_key_t*)private_key,
    //    pem_data,
    //    pem_size,
    //    _PUBLIC_KEY_MAGIC);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* private_key)
{
    return OE_UNSUPPORTED;
    // return oe_private_key_free(
    //    (oe_private_key_t*)private_key, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* public_key)
{
    return oe_bcrypt_key_free(public_key, _PUBLIC_KEY_MAGIC);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    return OE_UNSUPPORTED;
    // return oe_private_key_sign(
    //    (oe_private_key_t*)private_key,
    //    hash_type,
    //    hash_data,
    //    hash_size,
    //    signature,
    //    signature_size,
    //    _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_verify(
    const oe_ec_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(hash_type);

    NTSTATUS status = BCryptVerifySignature(
        ((const oe_bcrypt_key_t*)public_key)->pkey,
        NULL, /*paddingInfo depends on padding type below */
        hash_data,
        hash_size,
        signature,
        signature_size,
        NULL /* TODO: BCRYPT_PAD_PKCS1 or BCRYPT_PAD_PSS? */
    );

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "BCryptVerifySignature failed (err=%#x)\n",
            status);

    result = OE_OK;

done:
    return result;
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_generate_key_pair(
    oe_ec_type_t type,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    return OE_UNSUPPORTED;
    // return _generate_key_pair(
    //    type, (oe_private_key_t*)private_key, (oe_public_key_t*)public_key);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_generate_key_pair_from_private(
    oe_ec_type_t curve,
    const uint8_t* private_key_buf,
    size_t private_key_buf_size,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    return OE_UNSUPPORTED;
    //    oe_result_t result = OE_UNEXPECTED;
    //    int openssl_result;
    //    EC_KEY* key = NULL;
    //    BIGNUM* private_bn = NULL;
    //    EC_POINT* public_point = NULL;
    //    EVP_PKEY* public_pkey = NULL;
    //    EVP_PKEY* private_pkey = NULL;
    //
    //    if (!private_key_buf || !private_key || !public_key ||
    //        private_key_buf_size > OE_INT_MAX)
    //    {
    //        OE_RAISE(OE_INVALID_PARAMETER);
    //    }
    //
    //    /* Initialize OpenSSL. */
    //    oe_initialize_openssl();
    //
    //    /* Initialize the EC key. */
    //    key = EC_KEY_new_by_curve_name(_get_nid(curve));
    //    if (key == NULL)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    /* Set the EC named-curve flag. */
    //    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    //
    //    /* Load private key into the EC key. */
    //    private_bn = BN_bin2bn(private_key_buf, (int)private_key_buf_size,
    //    NULL);
    //
    //    if (private_bn == NULL)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    if (EC_KEY_set_private_key(key, private_bn) == 0)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    public_point = EC_POINT_new(EC_KEY_get0_group(key));
    //    if (public_point == NULL)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    /*
    //     * To get the public key, we perform the elliptical curve point
    //     * multiplication with the factors being the private key and the base
    //     * generator point of the curve.
    //     */
    //    openssl_result = EC_POINT_mul(
    //        EC_KEY_get0_group(key), public_point, private_bn, NULL, NULL,
    //        NULL);
    //    if (openssl_result == 0)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    /* Sanity check the params. */
    //    if (EC_KEY_set_public_key(key, public_point) == 0)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    if (EC_KEY_check_key(key) == 0)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    /* Map the key to the EVP_PKEY wrapper. */
    //    public_pkey = EVP_PKEY_new();
    //    if (public_pkey == NULL)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    if (EVP_PKEY_set1_EC_KEY(public_pkey, key) == 0)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    private_pkey = EVP_PKEY_new();
    //    if (private_pkey == NULL)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    if (EVP_PKEY_set1_EC_KEY(private_pkey, key) == 0)
    //        OE_RAISE(OE_CRYPTO_ERROR);
    //
    //    oe_ec_public_key_init(public_key, public_pkey);
    //    oe_ec_private_key_init(private_key, private_pkey);
    //    public_pkey = NULL;
    //    private_pkey = NULL;
    //    result = OE_OK;
    //
    // done:
    //    if (key != NULL)
    //        EC_KEY_free(key);
    //    if (private_bn != NULL)
    //        BN_clear_free(private_bn);
    //    if (public_point != NULL)
    //        EC_POINT_clear_free(public_point);
    //    if (public_pkey != NULL)
    //        EVP_PKEY_free(public_pkey);
    //    if (private_pkey != NULL)
    //        EVP_PKEY_free(private_pkey);
    //    return result;
}

oe_result_t _bcrypt_get_key_blob(
    oe_bcrypt_key_t* key,
    LPCWSTR blob_type,
    BYTE** key_blob,
    ULONG* key_blob_size)
{
    oe_result_t result = OE_UNEXPECTED;
    ULONG returned_blob_size = 0;
    NTSTATUS status = BCryptExportKey(
        key->pkey, NULL, blob_type, NULL, 0, &returned_blob_size, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptExportKey failed (status=%#x)\n", status);

    *key_blob = (BYTE*)malloc(returned_blob_size);
    if (!key_blob)
        OE_RAISE(OE_OUT_OF_MEMORY);
    *key_blob_size = returned_blob_size;

    status = BCryptExportKey(
        key->pkey,
        NULL,
        blob_type,
        *key_blob,
        *key_blob_size,
        &returned_blob_size,
        0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptExportKey failed (status=%#x)\n", status);

    if (returned_blob_size != *key_blob_size)
        OE_RAISE_MSG(
            OE_UNEXPECTED,
            "BCryptExportKey wrote fewer bytes than expected (exp=%d, "
            "wrote=%d)\n",
            *key_blob,
            returned_blob_size);

    result = OE_OK;

done:
    if (result != OE_OK && *key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(*key_blob);
        *key_blob = NULL;
        *key_blob_size = 0;
    }

    return result;
}

oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* public_key1,
    const oe_ec_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;
    BCRYPT_ECCKEY_BLOB* ec1 = NULL;
    ULONG ec1_size = 0;
    BCRYPT_ECCKEY_BLOB* ec2 = NULL;
    ULONG ec2_size = 0;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_bcrypt_key_is_valid(public_key1, _PUBLIC_KEY_MAGIC) ||
        !oe_bcrypt_key_is_valid(public_key2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_bcrypt_get_key_blob(
        (oe_bcrypt_key_t*)public_key1, BCRYPT_ECCPUBLIC_BLOB, &ec1, &ec1_size));

    OE_CHECK(_bcrypt_get_key_blob(
        (oe_bcrypt_key_t*)public_key2, BCRYPT_ECCPUBLIC_BLOB, &ec2, &ec2_size));

    /* See documentation of BCRYPT_ECCKEY_BLOB at:
     https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/ns-bcrypt-_bcrypt_ecckey_blob
     struct BCRYPT_ECCPUBLIC_BLOB
     {
        struct BCRYPT_ECCKEY_BLOB
        {
            ULONG dwMagic;
            ULONG cbKey;
        };
        BYTE X[cbKey]; // Big-endian
        BYTE Y[cbKey]; // Big-endian
     }
     All fields must match between the two EC keys to be equal.
     */
    if (ec1_size == ec2_size &&
        oe_constant_time_mem_equal(ec1, ec2, ec1_size) == 0)
    {
        *equal = true;
    }

    result = OE_OK;

done:
    if (ec1)
    {
        oe_secure_zero_fill(ec1, ec1_size);
        free(ec1);
        ec1 = NULL;
    }
    if (ec2)
    {
        oe_secure_zero_fill(ec2, ec2_size);
        free(ec2);
        ec2 = NULL;
    }

    return result;
}

oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* public_key,
    oe_ec_type_t ec_type,
    const uint8_t* x_data,
    size_t x_size,
    const uint8_t* y_data,
    size_t y_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t ecc_key_buffer_size = 0;
    uint8_t* ecc_key_buffer = NULL;
    BCRYPT_KEY_HANDLE ecc_key_handle = NULL;

    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!public_key || !x_data || !x_size || x_size > OE_INT_MAX || !y_data ||
        !y_size || y_size > OE_INT_MAX || x_size != y_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Construct a BCRYPT_ECCPUBLIC_BLOB */
    {
        ecc_key_buffer_size = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * x_size;
        ecc_key_buffer = (uint8_t*)malloc(ecc_key_buffer_size);
        if (!ecc_key_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);

        /* TODO: check struct alignment */
        BCRYPT_ECCKEY_BLOB* ecc_key_blob = (BCRYPT_ECCKEY_BLOB*)ecc_key_buffer;
        DWORD ecc_key_magic = _get_bcrypt_magic(ec_type);
        if (ecc_key_magic == OE_BCRYPT_UNSUPPORTED_EC_TYPE)
            OE_RAISE_MSG(
                OE_UNSUPPORTED,
                "oe_ec_public_key_from_coordinates does not support "
                "ec_type=%#x\n",
                ec_type);
        ecc_key_blob->dwMagic = ecc_key_magic;
        ecc_key_blob->cbKey = x_size;

        uint8_t* ecc_key_x = ecc_key_buffer + sizeof(BCRYPT_ECCKEY_BLOB);
        uint8_t* ecc_key_y = ecc_key_x + x_size;

        /* TODO: check if leading zero is needed */
        oe_memcpy_s(ecc_key_x, x_size, x_data, x_size);
        oe_memcpy_s(ecc_key_y, y_size, y_data, y_size);
    }

    /* Import the key blob to obtain the key handle */
    {
        BOOL success = BCryptImportKeyPair(
            BCRYPT_ECDSA_P256_ALG_HANDLE,
            NULL,
            BCRYPT_ECCPUBLIC_BLOB,
            &ecc_key_handle,
            ecc_key_buffer,
            (DWORD)ecc_key_buffer_size,
            0); /* No dwFlags */

        if (!success)
        {
            DWORD err = GetLastError();
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR, "BCryptImportKeyPair failed(err=%#x)\n", err);
        }

        /* wrap as oe_ec_public_key_t compatible type */
        oe_bcrypt_key_t* ecc_key = (oe_bcrypt_key_t*)public_key;
        ecc_key->magic = _PUBLIC_KEY_MAGIC;
        ecc_key->pkey = ecc_key_handle;
        ecc_key_handle = NULL;
    }

    result = OE_OK;

done:
    if (ecc_key_buffer)
    {
        oe_secure_zero_fill(ecc_key_buffer, ecc_key_buffer_size);
        free(ecc_key_buffer);
    }

    if (ecc_key_handle)
        BCryptDestroyKey(ecc_key_handle);

    return result;
}

oe_result_t oe_ecdsa_signature_write_der(
    unsigned char* signature,
    size_t* signature_size,
    const uint8_t* r_data,
    size_t r_size,
    const uint8_t* s_data,
    size_t s_size)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Reject invalid parameters */
    if (!signature_size || signature_size > MAXDWORD || !r_data || !r_size ||
        r_size > OE_INT_MAX || !s_data || !s_size || s_size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature is null, then signature_size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        /* TODO: Verify endian is compatible with sgx_ecdsa256_signature_t*/
        /* TODO: Verify leading-zero encoding does not cause issues */
        DWORD encoded_size = *signature_size;
        CERT_ECC_SIGNATURE ecc_sig;
        ecc_sig.r.cbData = r_size;
        ecc_sig.r.pbData = r_data;
        ecc_sig.s.cbData = s_size;
        ecc_sig.s.pbData = s_data;

        BOOL success = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            &ecc_sig,
            CRYPT_ENCODE_ALLOC_FLAG,
            NULL,
            &signature,
            &encoded_size);

        if (!success)
        {
            DWORD err = GetLastError();
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR, "CryptEncodeObjectEx failed (err=%#x)\n", err);
        }

        /* Check whether buffer is too small */
        if ((size_t)encoded_size > *signature_size)
        {
            *signature_size = (size_t)encoded_size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Set the size of the output buffer */
        *signature_size = (size_t)encoded_size;
    }

    result = OE_OK;

done:
    return result;
}

/* Used by tests/crypto/ec_tests */
bool oe_ec_valid_raw_private_key(
    oe_ec_type_t type,
    const uint8_t* key,
    size_t keysize)
{
    return OE_UNSUPPORTED;
    //    BIGNUM* bn = NULL;
    //    EC_GROUP* group = NULL;
    //    BIGNUM* order = NULL;
    //    bool is_valid = false;
    //
    //    if (!key || keysize > OE_INT_MAX)
    //        goto done;
    //
    //    bn = BN_bin2bn(key, (int)keysize, NULL);
    //    if (bn == NULL)
    //        goto done;
    //
    //    order = BN_new();
    //    if (order == NULL)
    //        goto done;
    //
    //    group = EC_GROUP_new_by_curve_name(_get_nid(type));
    //    if (group == NULL)
    //        goto done;
    //
    //    if (EC_GROUP_get_order(group, order, NULL) == 0)
    //        goto done;
    //
    //    /* Constraint is 1 <= private_key <= order - 1. */
    //    if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0)
    //        goto done;
    //
    //    is_valid = true;
    //
    // done:
    //    if (bn != NULL)
    //        BN_clear_free(bn);
    //    if (group != NULL)
    //        EC_GROUP_clear_free(group);
    //    if (order != NULL)
    //        BN_clear_free(order);
    //    return is_valid;
}
