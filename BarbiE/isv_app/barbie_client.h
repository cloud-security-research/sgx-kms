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
#ifndef _BC_COMMON_H_
#define _BC_COMMON_H_

#if defined(__cplusplus)
extern "C" {
#endif
/*!
*   Generate a symmetric key of user defined size, returned in sealed form
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param key_len - desired plain text key length (bytes)
*   @param[out] sealed_key - sealed_key_len byte buffer to store sealed key material
*   @param sealed_key_len - seal buffer len for key material
*/
int crypto_generate_key(sgx_enclave_id_t enclave_id, size_t key_len, uint8_t *sealed_key, size_t sealed_key_len);
/*!
*   Compare 2 buffers (internally calls memcmp)
*   @return SGX_INVALID_PARAMETER if input buffer failure detected, memcmp return otherwise
*   @param[in] buf1 first buffer for comparison
*   @param[in] buf2 second buffer for comparison
*/
int crypto_cmp(uint8_t *buf1, uint8_t *buf2, size_t len);
/*!
*   Securely, from within the enclave, compare contents of 2 sealed buffers (internally calls memcmp on plain text)
*   @return SGX_INVALID_PARAMETER if input buffer failure detected, memcmp return otherwise
*   @param enclave_id - target enclave handle
*   @param[in] sealed_key1 - first buffer for comparison
*   @param sealed_len1 - size of sealed_key1
*   @param[in] sealed_key2 - second buffer for comparison
*   @param sealed_len2 - size of sealed_key2
*/
int crypto_sealed_cmp(sgx_enclave_id_t enclave_id, uint8_t *sealed_key1, size_t sealed_len1, uint8_t *sealed_key2, size_t sealed_len2);
/*!
*   Securely encrypt contents of sealed buffer with with key material retrieved from another sealed buffer
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param[in] sealed_key - key used to generate enc_secret
*   @param sealed_key_len - size of sealed_key
*   @param[in] sealed_secret - secret to transport
*   @param sealed_secret_len - size of sealed_secret
*   @param[out] enc_secret - plain text recovered from sealed_secret encrypted with key retrieved from sealed_key
*   @param enc_secret_len
*   @param[out] secret_iv - iv of enc_secret
*   @param[out] secret_mac - mac of enc_secret
*   @param[in] project_id - aad for encrypt sk
*   @param[in] project_id_len
*/
int crypto_transport_secret(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, uint8_t *sealed_secret, size_t sealed_secret_len, uint8_t *enc_secret, size_t enc_secret_len, uint8_t *secret_iv, uint8_t *secret_mac, uint8_t *project_id, size_t project_id_len);
/*!
*   Securely encrypt plain text with with key material retrieved from sealed key.
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param[in] sealed_key - key used to generate cypher_text
*   @param sealed_len - size of sealed_key
*   @param[in] plain_text - buffer to be encrypted
*   @param plain_text_len - size of plain_text
*   @param[out] cypher_text - cypher text generated from input sealed_key material and plain_text
*   @param[out] secret_iv - iv of enc_secret
*   @param[out] secret_mac - mac of enc_secret
*/
int crypto_encrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac);
int crypto_legacy_encrypt(uint8_t *key, size_t key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac);
/*!
*   Securely decrypt cypher text with with key material retrieved from sealed key.
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param[in] sealed_key - key used to generate cypher_text
*   @param sealed_len - size of sealed_key
*   @param[out] plain_text - plain text recovered from input key material, cypher text, and metadata
*   @param plain_text_len - size of plain_text
*   @param[out] cypher_text - cypher text generated from input sealed_key material and plain_text
*   @param[in] iv - iv of cypher_text
*   @param[in] mac - mac of cypher_text
*/
int crypto_decrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len);
#if defined(__cplusplus)
}
#endif

#endif /* !_BC_COMMON_H_ */
