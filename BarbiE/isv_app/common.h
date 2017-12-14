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
#ifndef _B_COMMON_H_
#define _B_COMMON_H_

#if defined(__cplusplus)
extern "C" {
#endif
/*!
*   Create the enclave
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param[out] enclave_id - target enclave handle
*/
int initialize_enclave(sgx_enclave_id_t *enclave_id);
/*!
*   Destroy the Barbican enclave
*   @param enclave_id - target enclave handle
*/
void destroy_enclave(sgx_enclave_id_t enclave_id);
/*!
*   Gets the required sealed buffer size given plain text size
*   @return size_t - size in bytes required for seal buffer
*   @param enclave_id - target enclave handle
*   @param add - add info size
*   @param plain_len - plain text buffer size
*/
size_t get_sealed_data_len(sgx_enclave_id_t enclave_id, size_t add, size_t plain_len);
/*!
*   Gets the required add info size given sealed buffer size
*   @return size_t - size in bytes required for add info
*   @param enclave_id - target enclave handle
*   @param[in] sealed_buf_ptr - sealed buffer of interst
*   @param sealed_len - size of sealed_len
*/
size_t get_add_mac_len(sgx_enclave_id_t enclave_id, uint8_t* sealed_buf_ptr, uint32_t sealed_len);
/*!
*   Gets the required plain text size given sealed buffer
*   @return size_t - size in bytes required for plain text
*   @param enclave_id - target enclave handle
*   @param[in] sealed_buf_ptr - sealed buffer of interst
*   @param sealed_len - size of sealed_len
*/
size_t get_encrypted_len(sgx_enclave_id_t enclave_id, uint8_t* sealed_buf_ptr, uint32_t sealed_len);

/*!
*   Securely recover KEK from SK encrypted KEK and returns sealed form
*   @return sgx_status_t - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param[in] sealed_sk- sealed SK
*   @param sealed_sk_len
*   @param[in] sk_enc_kek - KEK encrypted with SK
*   @param sk_enc_kek_len
*   @param[in] iv
*   @param[in] mac
*   @param[in] sealed_kek -sealed KEK
*   @param sealed_kek_len
*/
int crypto_provision_kek(sgx_enclave_id_t enclave_id, uint8_t *sealed_sk, size_t sealed_sk_len, uint8_t *sk_enc_kek, size_t sk_enc_kek_len, uint8_t *iv, uint8_t *mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *project_id, size_t project_id_len);

unsigned char *makeByteArray(char *str);

#if defined(__cplusplus)
}
#endif

#endif /* !_B_COMMON_H_ */
