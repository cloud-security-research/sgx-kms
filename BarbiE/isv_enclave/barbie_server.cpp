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

//#include "Enclave_t.h"  /* print_string */
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include <string.h>    // memcpy
#include "seal.h"
#define IV_SIZE 12

sgx_status_t ecall_store_secret(uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len)
{
    if (!kek_enc_sk || !sk_iv || !sk_mac || !sealed_kek || !sk_enc_secret || !kek_enc_secret || !iv || !mac) return SGX_ERROR_INVALID_PARAMETER;
	sgx_status_t status = SGX_SUCCESS;
    uint8_t *plain_secret = (uint8_t *) malloc(sk_enc_secret_len);
    uint8_t *plain_sk = (uint8_t *) malloc(kek_enc_sk_len);
    status = ecall_decrypt(sealed_kek, sealed_kek_len, plain_sk, kek_enc_sk_len, kek_enc_sk, sk_iv, sk_mac, project_id, project_id_len);
    if (status != SGX_SUCCESS) goto exit;
	status = sgx_rijndael128GCM_decrypt(reinterpret_cast<uint8_t (*)[16]>(plain_sk), sk_enc_secret, sk_enc_secret_len, plain_secret, iv, IV_SIZE, NULL, 0, reinterpret_cast<uint8_t (*)[16]>(mac));
	if(SGX_SUCCESS != status)
	{
		printf("error decrypting cypher text\n");
	}
    status = ecall_encrypt(sealed_kek, sealed_kek_len, plain_secret, sk_enc_secret_len, kek_enc_secret, iv, mac, NULL, 0);
exit:
    memset_s(plain_secret, sk_enc_secret_len, 0, sk_enc_secret_len);
    memset_s(plain_sk, kek_enc_sk_len, 0, kek_enc_sk_len);
    free(plain_secret);
    free(plain_sk);
    return status;
}

sgx_status_t ecall_get_secret(uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len)
{
    if (!kek_enc_sk || !sk_iv || !sk_mac || !sealed_kek || !sk_enc_secret || !kek_enc_secret || !iv || !mac) return SGX_ERROR_INVALID_PARAMETER;
	sgx_status_t status = SGX_SUCCESS;
    uint8_t *plain_secret = (uint8_t *) malloc(kek_enc_secret_len);
    uint8_t *plain_sk = (uint8_t *) malloc(kek_enc_sk_len);
    status = ecall_decrypt(sealed_kek, sealed_kek_len, plain_sk, kek_enc_sk_len, kek_enc_sk, sk_iv, sk_mac, project_id, project_id_len);
    if (status != SGX_SUCCESS) goto exit;
    status = ecall_decrypt(sealed_kek, sealed_kek_len, plain_secret, kek_enc_secret_len, kek_enc_secret, iv, mac, NULL, 0);
    if (status != SGX_SUCCESS) goto exit;
	status = sgx_rijndael128GCM_encrypt(reinterpret_cast<uint8_t (*)[16]>(plain_sk),
            plain_secret, kek_enc_secret_len, sk_enc_secret, iv, IV_SIZE, NULL, 0, reinterpret_cast<uint8_t (*)[16]>(mac));
	if(SGX_SUCCESS != status)
	{
		printf("error encrypting plain text\n");
	}
exit:
    memset_s(plain_secret, sk_enc_secret_len, 0, sk_enc_secret_len);
    memset_s(plain_sk, kek_enc_sk_len, 0, kek_enc_sk_len);
    free(plain_secret);
    free(plain_sk);
    return status;
}

sgx_status_t ecall_provision_kek(uint8_t *sealed_sk, size_t sealed_sk_len, uint8_t *sk_enc_kek, size_t sk_enc_kek_len, uint8_t *iv, uint8_t *mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *project_id, size_t project_id_len)
{
    sgx_status_t status = SGX_SUCCESS;
    if (!sealed_sk || !sk_enc_kek || !iv || !mac || !sealed_kek) return SGX_ERROR_INVALID_PARAMETER; //todo return sgx_status_t SGX_ERROR_INVALID_PARAMETER;
    uint8_t *plain_kek = (uint8_t *) malloc(sk_enc_kek_len);
    status = ecall_decrypt(sealed_sk, sealed_sk_len, plain_kek, sk_enc_kek_len, sk_enc_kek, iv, mac, project_id, project_id_len);
    if(SGX_SUCCESS != status) goto exit;
    seal(sealed_kek, sealed_kek_len, plain_kek, sk_enc_kek_len);
exit:
    memset_s(plain_kek, sk_enc_kek_len, 0, sk_enc_kek_len);
    free(plain_kek);
    return status;
}

