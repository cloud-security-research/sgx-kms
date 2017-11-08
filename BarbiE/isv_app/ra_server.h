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
#ifndef _BS_H_
#define _BS_H_
#include <stdbool.h>
#if defined(__cplusplus)
extern "C" {
#endif
/*!
*   Processes RA MSG0.  Dummy implementation at present, does nothing significant with the message
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param[in] pp_msg_full - RA MSG0 + header.  Warning API allocates memory, caller responsible to free resources
*   @param[out] pp_ra_ctx - RA session context
*/
int proc_msg0(ra_samp_msg0_request_header_t *p_msg_full, void **pp_ra_ctx, uint8_t *spid, bool client_verify_ias);
/*!
*   Processes RA MSG1 and if successful generates RA MSG2
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param[in] pp_msg_full - RA MSG1 + header
*   @param[in/out] pp_ra_ctx - RA session context
*   @param[out] pp_msg_resp_full - RA MSG2 + header.  Warning API allocates memory, callre responsible to free resources
*/
int proc_msg1(ra_samp_msg1_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_msg1_response_header_t **pp_msg_resp_full);
/*!
*   Processes RA MSG3 and if successful generates RA MSG4
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param[in] pp_msg_full - RA MSG3 + header
*   @param[in/out] pp_ra_ctx - RA session context
*   @param[out] pp_msg_resp_full - RA MSG4 + header.  Warning API allocates memory, callre responsible to free resources
*   @param[in] uint8_t* project_id 
*/
int proc_msg3(ra_samp_msg3_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_msg3_response_header_t **pp_msg_resp_full, uint8_t *project_id, uint8_t *ias_crt, bool client_verify_ias);
/*!
*   Recovers SK from RA_DH enc_sk
*   @return sp_ra_msg_status_t (as int) - SP_OK on success, error code otherwise
*   @param[in/out] pp_ra_ctx - RA session context
*   @param[out] plain_sk - plain text SK
*   @param sk_len
*   @param[in] enc_sk - RA_DH encrypted SK
*   @param[in] sk_iv
*   @param[in] sk_mac
*/
int get_sk(void **pp_ra_ctx, uint8_t *plain_sk, size_t sk_len, uint8_t *enc_sk, uint8_t *sk_iv, uint8_t *sk_mac);
/*!
*   Returns MRENCLAVE by member offset of RA MSG3
*   @return uint8_t* - MRENCLAVE
*   @param[in] p_msg3 - RA MSG3 + header
*/
uint8_t *get_mr_e(ra_samp_msg3_request_header_t *p_msg3);
/*!
*   Returns MRSIGNER by member offset of RA MSG3
*   @return uint8_t* - MRSIGNER
*   @param[in] p_msg3 - RA MSG3 + header
*/
uint8_t *get_mr_s(ra_samp_msg3_request_header_t *p_msg3);
#if defined(__cplusplus)
}
#endif

#endif /* !_BS_H_ */
