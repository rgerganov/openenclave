// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/bits/defs.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sha.h>
#include "../common/common.h"

// Using mbedtls to create an extended X.509 certificate
#include "mbedtls_corelibc_defs.h"
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include "mbedtls_corelibc_undef.h"
// clang-format on

static unsigned char oid_oe_report[] = X509_OID_FOR_QUOTE_EXT;

static int extract_x509_quote_ext(
    uint8_t* ext3_data,
    size_t exts_data_len,
    const uint8_t* report_oid,
    size_t report_oid_len,
    uint8_t** report_data,
    size_t* report_data_size)
{
    int ret = 1;
    unsigned char* p = NULL;
    const unsigned char* end = NULL;
    mbedtls_x509_buf oid = {MBEDTLS_ASN1_OID, 0, NULL};
    unsigned char* end_seq_data;
    int is_critical;
    size_t len = 0;
    size_t sequence_len = 0;

    p = (unsigned char*)ext3_data;
    end = p + exts_data_len;

    if (mbedtls_asn1_get_tag(
            &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) !=
        0)
    {
        OE_TRACE_ERROR("Attribute: SEQUENCE not found in extension blob");
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto done;
    }

    // Search for target report OID
    while (p < end)
    {
        is_critical = 0; /* DEFAULT FALSE */
        if (mbedtls_asn1_get_tag(
                &p,
                end,
                &sequence_len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            OE_TRACE_ERROR(
                "Attribute: expected SEQUENCE not found in extension blob");
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            goto done;
        }
        OE_TRACE_VERBOSE("SEQUENCE len: %d", sequence_len);

        end_seq_data = p + sequence_len;

        /* Get extension OID ID */
        oid.tag = *p;
        if (mbedtls_asn1_get_tag(&p, end, &oid.len, MBEDTLS_ASN1_OID) != 0)
        {
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            goto done;
        }
        oid.p = p;

        // Skip standard standard extensions:  basic constrains, subject key id,
        // authority key id
        if ((MBEDTLS_OID_CMP(MBEDTLS_OID_BASIC_CONSTRAINTS, &oid) == 0) ||
            (MBEDTLS_OID_CMP(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER, &oid) == 0) ||
            (MBEDTLS_OID_CMP(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER, &oid) == 0))
        {
            p = end_seq_data;
            continue;
        }

        OE_TRACE_INFO("report_oid_len=%d len=%d", report_oid_len, len);
        // Check against target OID
        if ((oid.len == report_oid_len) &&
            (0 == memcmp(oid.p, report_oid, report_oid_len)))
        {
            p += report_oid_len;
            if ((ret = mbedtls_asn1_get_tag(
                     &p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0)
            {
                OE_TRACE_ERROR("Read quote extension failed with ret=%d", ret);
                goto done;
            }
            *report_data = p;
            *report_data_size = len;
            break;
        }
        p = end_seq_data;
    }
done:
    if (ret)
        OE_TRACE_ERROR("Expected x509 quote extension not found");

    return ret;
}

static oe_result_t get_x509_report_extension(
    mbedtls_x509_crt* cert,
    uint8_t** report_data,
    size_t* report_data_size)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;

    ret = extract_x509_quote_ext(
        cert->v3_ext.p,
        cert->v3_ext.len,
        oid_oe_report,
        sizeof(oid_oe_report),
        report_data,
        report_data_size);
    if (ret)
        OE_RAISE(OE_FAILURE, "ret = %d", ret);

    OE_TRACE_VERBOSE(
        "report_data = %p report_data[0]=0x%x report_data_size=%d",
        *report_data,
        **report_data,
        *report_data_size);
    result = OE_OK;

done:
    return result;
}

// verify report user data against peer certificate
oe_result_t verify_report_user_data(
    mbedtls_x509_crt* cert,
    uint8_t* report_data)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;
    uint8_t pk_buf[OE_RSA_KEY_BUFF_SIZE];
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256;

    oe_memset_s(pk_buf, sizeof(pk_buf), 0, sizeof(pk_buf));
    ret = mbedtls_pk_write_pubkey_pem(&cert->pk, pk_buf, sizeof(pk_buf));
    if (ret)
        OE_RAISE_MSG(OE_FAILURE, "ret = %d", ret);

    OE_TRACE_VERBOSE(
        "pk_buf=[%s] \n oe_strlen(pk_buf)=[%d]",
        pk_buf,
        oe_strlen((const char*)pk_buf));

    // create a hash of public key
    oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(
        &sha256_ctx,
        pk_buf,
        oe_strlen((const char*)pk_buf) + 1)); // +1 for the ending null char
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    // validate report's user data against hash(public key)
    if (memcmp(report_data, (uint8_t*)&sha256, OE_SHA256_SIZE) != 0)
    {
        for (int i = 0; i < OE_SHA256_SIZE; i++)
            OE_TRACE_VERBOSE(
                "[%d] report_data[0x%x] sha256=0x%x ",
                i,
                report_data[i],
                sha256.buf[i]);
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "hash of peer certificate's public key does not match report data",
            NULL);
    }
    result = OE_OK;
done:
    return result;
}

oe_result_t verify_cert_signature(mbedtls_x509_crt* cert)
{
    oe_result_t result = OE_FAILURE;
    uint32_t flags = 0;
    int ret = 0;

    ret = mbedtls_x509_crt_verify(cert, cert, NULL, NULL, &flags, NULL, NULL);
    if (ret)
    {
        oe_verify_cert_error_t error;
        mbedtls_x509_crt_verify_info(error.buf, sizeof(error.buf), "", flags);
        OE_RAISE_MSG(
            OE_FAILURE,
            "mbedtls_x509_crt_verify failed with %s (flags=0x%x)",
            error.buf,
            flags);
    }
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_verify_tls_cert(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_enclave_identity_verify_callback_t enclave_identity_callback,
    void* arg)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* report = NULL;
    size_t report_size = 0;
    oe_report_t parsed_report = {0};
    int ret;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    // create a mbedtls cert object from encoded cert data in DER format
    ret = mbedtls_x509_crt_parse(&cert, cert_in_der, cert_in_der_len);
    if (ret)
        OE_RAISE_MSG(OE_FAILURE, "ret = %d", ret);

    // validate the certificate signature
    result = verify_cert_signature(&cert);
    OE_CHECK(result);

    OE_CHECK(get_x509_report_extension(&cert, &report, &report_size));
    OE_TRACE_VERBOSE(
        "report = %p report[0]=0x%x report_size=%d",
        report,
        *report,
        report_size);

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now

    result = oe_verify_report(report, report_size, &parsed_report);
    OE_CHECK(result);
    OE_TRACE_VERBOSE("oe_verify_report() succeeded");

    // verify report size and type
    if (parsed_report.size != sizeof(oe_report_t))
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "Unexpected parsed_report.size: %d (expected value:%d) ",
            parsed_report.size,
            sizeof(oe_report_t));

    if (parsed_report.type != OE_ENCLAVE_TYPE_SGX)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "Report type is not supported: parsed_report.type (%d)",
            parsed_report.type);

    // verify report's user data
    result = verify_report_user_data(&cert, parsed_report.report_data);
    OE_CHECK(result);

    // invoke a client callback for customized enclave identity check
    if (enclave_identity_callback)
    {
        result = enclave_identity_callback(&parsed_report.identity, arg);
        OE_CHECK(result);
    }
    else
    {
        OE_TRACE_WARNING(
            "No enclave_identity_callback provided in oe_verify_tls_cert call",
            NULL);
    }
done:
    mbedtls_x509_crt_free(&cert);
    return result;
}
