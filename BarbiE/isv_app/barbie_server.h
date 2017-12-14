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
#ifndef _BS_COMMON_H_
#define _BS_COMMON_H_

#if defined(__cplusplus)
extern "C" {
#endif
/*!
*   Securely decrypt user symmetric key (SK) encrypted secret and encrypt with key encryption key (KEK) retreived from sealed kek blob
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param[in] kek_enc_sk - SK encrypted with KEK
*   @param kek_enc_sk_len
*   @param[in] sk_iv
*   @param[in] sk_mac
*   @param[in] sealed_kek
*   @param sealed_kek_len
*   @param[in] sk_enc_secret - user secret encrypted with SK
*   @param sk_enc_secret_len
*   @param[out] kek_enc_secret - user secret encrypted with KEK
*   @param kek_enc_secret_len
*   @param[out] iv
*   @param[out] mac
*   @param[in] project_id - aad for sk decrypt 
*   @param[in] project_id_len
*/
int crypto_store_secret(sgx_enclave_id_t enclave_id, uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len);
/*!
*   Securely decrypt user key encryption key (KEK) encrypted secret and encrypt with symmetric key (SK)
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param[in] kek_enc_sk - SK encrypted with KEK
*   @param kek_enc_sk_len
*   @param[in] sk_iv
*   @param[in] sk_mac
*   @param[in] sealed_kek
*   @param sealed_kek_len
*   @param[out] sk_enc_secret - user secret encrypted with SK
*   @param sk_enc_secret_len
*   @param[in] kek_enc_secret - user secret encrypted with KEK
*   @param kek_enc_secret_len
*   @param[out] iv
*   @param[out] mac
*/
int crypto_get_secret(sgx_enclave_id_t enclave_id, uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len);
#if defined(__cplusplus)
}
#endif

#endif /* !_BS_COMMON_H_ */
