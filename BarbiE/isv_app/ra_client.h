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
#ifndef _RA_C_H_
#define _RA_C_H_

#if defined(__cplusplus)
extern "C" {
#endif
/*!
*   Generates RA MSG0
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param[out] pp_msg0_full - RA MSG0 + header.  Warning API allocates memory, caller responsible to free resources
*/
int gen_msg0(ra_samp_msg0_request_header_t **pp_msg0_full, uint8_t *spid);
/*!
*   Generates RA MSG1
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param[out] context - SGX RA session context handle
*   @param[out] pp_msg1_full - RA MSG1 + header.  Warning API allocates memory, caller responsible to free resources
*/
int gen_msg1(sgx_enclave_id_t enclave_id, sgx_ra_context_t *context, ra_samp_msg1_request_header_t **pp_msg1_full, char *pub_key);
/*!
*   Generates RA MSG3 if RA MSG2 processed successfully
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param context - SGX RA session context handle
*   @param[in] pp_msg2_full - RA MSG2 + header
*   @param[out] pp_msg3_full - RA MSG3 + header.  Warning API allocates memory, caller responsible to free resources
*/
int gen_msg3(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg1_response_header_t *p_msg2_full, ra_samp_msg3_request_header_t** pp_msg3_full, uint8_t *ias_crt, bool client_verify_ias, bool server_verify_ias, uint8_t* resp_crt, uint8_t* resp_sign, uint8_t* resp_body);
/*!
*   Processes RA MSG4 and if successful and secret payload exists returns the seealed secret
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param context - SGX RA session context handle
*   @param[in] pp_att_result_msg_full - RA MSG4 + header
*   @param[out] sealed_secret - sealed secret from MSG4 payload
*   @param sealed_len
*/
int proc_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_secret, size_t sealed_len, uint8_t *sealed_secret2, size_t secret2_len);

int ma_proc_ra(sgx_enclave_id_t enclave_id, ra_samp_msg3_response_header_t* s_msg4, sgx_ra_context_t s_p_ctxt, ra_samp_msg3_request_header_t *c_msg3, void **c_p_net_ctxt, ra_samp_msg3_response_header_t **pp_resp2, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *ias_crt, bool client_verify_ias, int policy, uint8_t *attribute, size_t attribute_len, uint8_t *iv1, uint8_t *mac1);

int new_proc_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *dh_sk, size_t dk_sk_len, uint8_t *iv1, uint8_t *mac1);

int get_kek(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *sk_kek, size_t sk_kek_len, uint8_t *iv1, uint8_t *mac1, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *project_id, size_t project_id_len);

int secret_encrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *sk_secret, size_t sk_secret_len, uint8_t *iv1, uint8_t *mac1, uint8_t *mk_secret, size_t plain_sk_len, uint8_t *iv2, uint8_t *mac2, uint8_t *project_id, size_t project_id_len);

int secret_decrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *mk_secret, size_t mk_secret_len, uint8_t *iv1, uint8_t *mac1, uint8_t *sk_secret, size_t plain_sk_len, uint8_t *iv2, uint8_t *mac2, uint8_t *project_id, size_t project_id_len);

int get_mk_mr_list(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, uint8_t *sk_mr_list, size_t sk_mr_list_len, uint8_t *project_id, size_t project_id_len, uint8_t *mk_mr_list, size_t mk_mr_list_len, uint8_t *new_mk_mr_list, uint8_t *iv1, uint8_t *mac1, uint8_t *iv2, uint8_t *mac2, uint8_t *iv3, uint8_t *mac3, uint8_t *iv, uint8_t *mac);

int get_sk_data(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, uint8_t *mk_data, size_t mk_data_len, uint8_t *project_id, size_t project_id_len, uint8_t *sk_data, uint8_t *iv1, uint8_t *mac1, uint8_t *iv2, uint8_t *mac2, uint8_t *iv, uint8_t *mac);
/*!
*   Processes RA MSG4 and provide project_id
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param context - SGX RA session context handle
*   @param[in] pp_att_result_msg_full - RA MSG4 + header
*   @param[out] project_id 
*/
int get_project_id(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *project_id);
/*!
*   Processes RA MSG4 and return project_id
*   @return  int - project_id_len from MSG4
*   @param enclave_id - target enclave handle
*   @param context - SGX RA session context handle
*   @param[in] pp_att_result_msg_full - RA MSG4 + header
*/
int get_project_id_len(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full);
/*!
*   Processes RA MSG4 and if successful and secret payload exists returns the seealed secret
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param context - SGX RA session context handle
*   @param[in] pp_att_result_msg_full - RA MSG4 + header
*   @param[out] sealed_secret - sealed DH key used for this RA session
*   @param sealed_len
*/
int get_dh_key(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_secret, size_t sealed_len);
/*!
*   Closes RA session
*   @return sgx_status_t (as int) - SGX_SUCCESS on success, error code otherwise
*   @param enclave_id - target enclave handle
*   @param context - SGX RA session context handle
*/
int close_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context);
#if defined(__cplusplus)
}
#endif

#endif /* !_RA_C_H_ */
