/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "isv_app.h"
#include "service_provider.h"
#include "../sample_libcrypto/sample_libcrypto.h"
#include "barbie_client.h"

int crypto_generate_key(sgx_enclave_id_t enclave_id, size_t key_len, uint8_t *sealed_key, size_t sealed_key_len)
{
    if (!sealed_key) return SGX_ERROR_INVALID_PARAMETER;
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    sgx_ret = ecall_generate_key(enclave_id, &status, key_len, sealed_key, sealed_key_len);
    if (sgx_ret != SGX_SUCCESS) return sgx_ret;
    return status;
}

int crypto_cmp(uint8_t *buf1, uint8_t *buf2, size_t len)
{
    if (!buf1 || !buf2) return SGX_ERROR_INVALID_PARAMETER;
    return memcmp(buf1, buf2, len);
}

int crypto_sealed_cmp(sgx_enclave_id_t enclave_id, uint8_t *sealed_key1, size_t sealed_len1, uint8_t *sealed_key2, size_t sealed_len2)
{
    int ret = 0;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_ret = ecall_sealed_cmp(enclave_id, &ret, sealed_key1, sealed_len1, sealed_key2, sealed_len2);
    if (sgx_ret != SGX_SUCCESS) return sgx_ret;
    return ret;
}

int crypto_transport_secret(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, uint8_t *sealed_secret, size_t sealed_secret_len, uint8_t *enc_secret, size_t enc_secret_len, uint8_t *secret_iv, uint8_t *secret_mac, uint8_t *project_id, size_t project_id_len)
{
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    sgx_ret = ecall_transport_secret(enclave_id, &status, sealed_key, sealed_key_len, sealed_secret, sealed_secret_len, enc_secret, enc_secret_len, secret_iv, secret_mac, project_id, project_id_len);
    if (sgx_ret != SGX_SUCCESS) return sgx_ret;
    return status;
}

int crypto_encrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac)
{
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    sgx_ret = ecall_encrypt(enclave_id, &status, sealed_key, sealed_key_len, (uint8_t *) plain_text, plain_text_len, cypher_text, iv, mac, NULL, 0);
    if (sgx_ret != SGX_SUCCESS) return sgx_ret;
    return status;
}

int crypto_legacy_encrypt(uint8_t *key, size_t key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac)
{
    int x = sample_rijndael128GCM_encrypt(reinterpret_cast<uint8_t (*)[16]>(key), (const uint8_t *) plain_text, plain_text_len, cypher_text, iv, SAMPLE_SP_IV_SIZE, NULL, 0, reinterpret_cast<uint8_t (*)[16]>(mac));
    return x;
}

int crypto_decrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac)
{
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    sgx_ret = ecall_decrypt(enclave_id, &status, sealed_key, sealed_key_len, (uint8_t *) plain_text, plain_text_len, cypher_text, iv, mac, NULL, 0);
    if (sgx_ret != SGX_SUCCESS) return sgx_ret;
    return status;
}
