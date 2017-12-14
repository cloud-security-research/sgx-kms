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
#include "barbie_server.h"

int crypto_store_secret(sgx_enclave_id_t enclave_id, uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len)
{
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    sgx_ret = ecall_store_secret(enclave_id, &status, kek_enc_sk, kek_enc_sk_len, sk_iv, sk_mac, sealed_kek, sealed_kek_len, sk_enc_secret, sk_enc_secret_len, kek_enc_secret, kek_enc_secret_len, iv, mac, project_id, project_id_len);
    if (sgx_ret != SGX_SUCCESS) return sgx_ret;
    return status;
}

int crypto_get_secret(sgx_enclave_id_t enclave_id, uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *iv, uint8_t *mac,  uint8_t *project_id, size_t project_id_len)
{
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    sgx_ret = ecall_get_secret(enclave_id, &status, kek_enc_sk, kek_enc_sk_len, sk_iv, sk_mac, sealed_kek, sealed_kek_len, kek_enc_secret, kek_enc_secret_len, sk_enc_secret, sk_enc_secret_len, iv, mac, project_id, project_id_len);
    if (sgx_ret != SGX_SUCCESS) return sgx_ret;
    return status;
}

