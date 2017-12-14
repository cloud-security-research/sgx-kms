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



#ifndef _SERVICE_PROVIDER_H
#define _SERVICE_PROVIDER_H

#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_key_exchange.h"
#include "sgx_quote.h"
#include "remote_attestation_result.h"
#include "ias_ra.h"
#include "network_ra.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    SP_OK,
    SP_UNSUPPORTED_EXTENDED_EPID_GROUP,
    SP_INTEGRITY_FAILED,
    SP_QUOTE_VERIFICATION_FAILED,
    SP_IAS_FAILED,
    SP_INTERNAL_ERROR,
    SP_PROTOCOL_ERROR,
    SP_QUOTE_VERSION_ERROR,
    SP_SPID_SET_ERROR,
} sp_ra_msg_status_t;

#pragma pack(push,1)

#define SAMPLE_SP_TAG_SIZE       16
#define SAMPLE_SP_IV_SIZE        12

typedef struct sample_ec_pub_t
{
    uint8_t gx[SAMPLE_ECP_KEY_SIZE];
    uint8_t gy[SAMPLE_ECP_KEY_SIZE];
} sample_ec_pub_t;

//fixed length to align with internal structure
typedef struct sample_ps_sec_prop_desc_t
{
    uint8_t  sample_ps_sec_prop_desc[256];
} sample_ps_sec_prop_desc_t;

#pragma pack(pop)

typedef uint32_t                sample_ra_context_t;

typedef uint8_t                 sample_key_128bit_t[16];

typedef sample_key_128bit_t     sample_ra_key_128_t;

typedef struct sample_ra_msg0_t
{
    uint32_t                    extended_epid_group_id;
    uint8_t                    spid[32];
} sample_ra_msg0_t;


typedef struct sample_ra_msg1_t
{
    sample_ec_pub_t             g_a;        // the Endian-ness of Ga is
                                            // Little-Endian
    sample_epid_group_id_t      gid;        // the Endian-ness of GID is
                                            // Little-Endian
} sample_ra_msg1_t;

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
const uint16_t SAMPLE_AES_CMAC_KDF_ID = 0x0001;

typedef struct sample_ra_msg2_t
{
    sample_ec_pub_t             g_b;        // the Endian-ness of Gb is
                                            // Little-Endian
    sample_spid_t               spid;       // In little endian
    uint16_t                    quote_type; /* unlinkable Quote(0) or linkable Quote(0) in little endian*/
    uint16_t                    kdf_id;     /* key derivation function id in little endian. 
                                             0x0001 for AES-CMAC Entropy Extraction and Key Derivation */
    sample_ec_sign256_t         sign_gb_ga; // In little endian
    sample_mac_t                mac;        // mac_smk(g_b||spid||quote_type||
                                            //         sign_gb_ga)
    uint32_t                    sig_rl_size;
    uint8_t                  sig_rl[];
} sample_ra_msg2_t;

typedef struct sample_ra_msg3_t
{
    sample_mac_t                mac;        // mac_smk(g_a||ps_sec_prop||quote)
    sample_ec_pub_t             g_a;        // the Endian-ness of Ga is
                                            // Little-Endian
    sample_ps_sec_prop_desc_t   ps_sec_prop;
    uint8_t                  quote[];
} sample_ra_msg3_t;

int sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
    uint32_t msg0_size, uint8_t *in_spid);

int sp_ra_proc_msg1_req(void **pp_ra_ctx, const sample_ra_msg1_t *p_msg1,
						uint32_t msg1_size,
						ra_samp_response_header_t **pp_msg2,
						sgx_ec256_private_t* priv_key);

#define SK_KEY_SIZE 16
extern size_t get_sealed_data_len(sgx_enclave_id_t enclave_id, size_t add, size_t plain_len);
extern size_t get_encrypted_len(sgx_enclave_id_t enclave_id, uint8_t* sealed_buf_ptr, uint32_t sealed_len);
extern sgx_status_t server_put_secret_data(sgx_enclave_id_t eid, uint8_t* sealed_sk, size_t sealed_len, uint8_t* plain_ra_key, size_t plain_ra_key_len, uint8_t* ra_key_enc_sk, uint8_t* iv, uint8_t* mac);

int sp_ra_proc_msg3_req(void **pp_ra_ctx, sgx_ra_msg3_t *p_msg3, uint32_t msg3_size, ra_samp_response_header_t **pp_att_result_msg,
                        sgx_ra_msg3_t *c_p_msg3, uint8_t *project_id, uint8_t *owner_mr_e, uint8_t *ias_crt, bool client_verify_ias, sample_ra_att_result_msg_t *r_c_msg4_body);
int sp_get_sk(void **pp_ra_ctx, uint8_t *plain_sk, size_t sk_len, uint8_t *enc_sk, uint8_t *sk_iv, uint8_t *sk_mac);

int sp_ra_free_msg2(
    sgx_ra_msg2_t *p_msg2);

int set_enclave(void **pp_ra_ctx, sgx_enclave_id_t enclave_id);
int set_secret(void **pp_ra_ctx, uint8_t *secret, size_t secret_len, uint8_t *secret2, size_t secret2_len);
int ias_verify_attestation_evidence(
    uint8_t *p_isv_quote,
    uint8_t* pse_manifest,
    ias_att_report_t* p_attestation_verification_report, uint8_t *ias_crt,
    uint8_t *resp_crt, uint8_t *resp_sign, uint8_t *resp_body, bool fake_report);

typedef int (*sample_enroll)(int sp_credentials, sgx_spid_t* spid,
    int* authentication_token, uint8_t *in_spid);

typedef int(*sample_get_sigrl)(const sample_epid_group_id_t gid, uint32_t* p_sig_rl_size,
    uint8_t** p_sig_rl);

typedef int(*sample_verify_attestation_evidence)(uint8_t *p_isv_quote,
    uint8_t* pse_manifest,
    ias_att_report_t* attestation_verification_report, uint8_t *ias_crt, uint8_t *resp_crt, uint8_t *resp_sign, uint8_t *resp_body, bool fake_report);

uint8_t *sp_get_mr_e(sgx_ra_msg3_t *p_msg3);
uint8_t *sp_get_mr_s(sgx_ra_msg3_t *p_msg3);

int get_report_sha256(ra_samp_msg3_request_header_t *p_msg3, uint8_t *sha256);

typedef struct sample_extended_epid_group
{
    uint32_t extended_epid_group_id;
    sample_enroll enroll;
    sample_get_sigrl get_sigrl;
    sample_verify_attestation_evidence verify_attestation_evidence;
} sample_extended_epid_group;

#ifdef  __cplusplus
}
#endif

#endif
