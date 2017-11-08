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


#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include <string.h>    // memcpy
#include "seal.h"
#define IV_SIZE 12

sgx_status_t ecall_generate_key(size_t key_len, uint8_t *sealed_key, size_t sealed_key_len)
{
    if (!sealed_key || sealed_key_len < sgx_calc_sealed_data_size(0, key_len)) return SGX_ERROR_INVALID_PARAMETER;
    sgx_status_t status = SGX_SUCCESS;
	uint8_t* tmp = (uint8_t *) malloc(key_len);
    status = sgx_read_rand(tmp, key_len);
    if (status != SGX_SUCCESS) return status;
    status = (sgx_status_t) seal(sealed_key, sealed_key_len, tmp, key_len);
    memset_s(tmp, key_len, 0, key_len);
    free(tmp);
    tmp = NULL;
    return status;
}

int ecall_sealed_cmp(uint8_t *sealed_key1, size_t sealed_len1, uint8_t *sealed_key2, size_t sealed_len2)
{
    int ret;
	sgx_key_128bit_t key1, key2;
    if (!sealed_key1 || !sealed_key2) return SGX_ERROR_INVALID_PARAMETER;
    //todo: what if unseal fails...
    unseal(sealed_key1, sealed_len1, (uint8_t *) &key1, sizeof(sgx_key_128bit_t));
    unseal(sealed_key2, sealed_len2, (uint8_t *) &key2, sizeof(sgx_key_128bit_t));
    ret = memcmp((void *) &key1, (void *) &key2, sizeof(sgx_key_128bit_t));
    memset_s(&key1, sizeof(key1), 0, sizeof(key1));
    memset_s(&key2, sizeof(key2), 0, sizeof(key2));
    return ret;
}

sgx_status_t ecall_encrypt(uint8_t *sealed_key, size_t sealed_key_len, uint8_t *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len)
{
    if (!sealed_key || !plain_text || !cypher_text || !iv || !mac) return SGX_ERROR_INVALID_PARAMETER;
	sgx_status_t status = SGX_SUCCESS;
	sgx_key_128bit_t enc_key;
	status = (sgx_status_t) unseal(sealed_key, sealed_key_len, (uint8_t *) &enc_key, sizeof(sgx_key_128bit_t));
    if (status != SGX_SUCCESS) return status;
	status = sgx_rijndael128GCM_encrypt(&enc_key,
            plain_text, plain_text_len, cypher_text, iv, IV_SIZE, project_id, project_id_len, reinterpret_cast<uint8_t (*)[16]>(mac));
	if(SGX_SUCCESS != status)
	{
		printf("error encrypting plain text\n");
	}
    memset_s(&enc_key, sizeof(enc_key), 0, sizeof(enc_key));
    return status;
}

sgx_status_t ecall_decrypt(uint8_t *sealed_key, size_t sealed_key_len, uint8_t *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len)
{
    if (!sealed_key || !plain_text || !cypher_text || !iv || !mac) return SGX_ERROR_INVALID_PARAMETER;
	sgx_status_t status = SGX_SUCCESS;
	sgx_key_128bit_t dec_key;
	status = (sgx_status_t) unseal(sealed_key, sealed_key_len, (uint8_t *) &dec_key, sizeof(sgx_key_128bit_t));
    if (status != SGX_SUCCESS) return status;
	status = sgx_rijndael128GCM_decrypt(&dec_key, cypher_text, plain_text_len, plain_text, iv, IV_SIZE, project_id, project_id_len, reinterpret_cast<uint8_t (*)[16]>(mac));
	if(SGX_SUCCESS != status)
	{
		printf("\nError decrypting cypher text\n");
	}
    memset_s(&dec_key, sizeof(dec_key), 0, sizeof(dec_key));
    return status;
}

sgx_status_t ecall_transport_secret(uint8_t *sealed_key, size_t sealed_key_len, uint8_t *sealed_secret, size_t sealed_secret_len, uint8_t *enc_secret, size_t enc_secret_len, uint8_t *secret_iv, uint8_t *secret_mac, uint8_t *project_id, size_t project_id_len)
{
    sgx_status_t status = SGX_SUCCESS;
    if (!sealed_key || !sealed_secret || !enc_secret || !secret_iv || !secret_mac) return SGX_ERROR_INVALID_PARAMETER;
    size_t plain_secret_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t*) sealed_secret);
    uint8_t *plain_secret = (uint8_t *) malloc(plain_secret_len);
    status = (sgx_status_t) unseal(sealed_secret, sealed_secret_len, plain_secret, plain_secret_len);
    if (status != SGX_SUCCESS) return status;
    status = (sgx_status_t) ecall_encrypt(sealed_key, sealed_key_len, plain_secret, plain_secret_len, enc_secret, secret_iv, secret_mac, project_id, project_id_len);
    memset_s(plain_secret, plain_secret_len, 0, plain_secret_len);
    free(plain_secret);
    return status;
}

