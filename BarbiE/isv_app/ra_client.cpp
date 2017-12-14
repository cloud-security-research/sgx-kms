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

// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"
#include "ra_client.h"
#include "barbie_client.h"
#include "common.h"

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}

int gen_msg0(ra_samp_msg0_request_header_t **pp_msg0_full, uint8_t *spid)
{
    //todo check input
    int ret = 0;
    ra_samp_request_header_t *p_msg0_full = NULL;
    int32_t verify_index = -1;
    uint32_t extended_epid_group_id = 0;
    FILE* OUTPUT = stdout;
    sample_ra_msg0_t *p_msg0 = NULL;

    // Preparation for remote attestation by configuring extended epid group id.
    {
        ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
        if (SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].",
                __FUNCTION__);
            return ret;
        }
        fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

        p_msg0_full = (ra_samp_request_header_t*)
            malloc(sizeof(ra_samp_request_header_t)
            +sizeof(uint32_t) + 32*sizeof(uint8_t));

        p_msg0 = (sample_ra_msg0_t*)
            malloc(sizeof(uint32_t) + 32*sizeof(uint8_t));

        if (NULL == p_msg0_full)
        {
            ret = -1;
            return ret;
        }
        p_msg0_full->type = TYPE_RA_MSG0;
        p_msg0_full->size = sizeof(uint32_t) + 32*sizeof(uint8_t);
        p_msg0 = (sample_ra_msg0_t *)p_msg0_full->body;
        p_msg0->extended_epid_group_id = extended_epid_group_id;
        if(spid != NULL)
        {
		    strncpy((char *)p_msg0->spid, (char *)spid, 32);
        }

        //*(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
        {

            fprintf(OUTPUT, "\nMSG0 body generated -\n");

            PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

        }
        *pp_msg0_full = (ra_samp_msg0_request_header_t *)p_msg0_full;
    }
    return ret;
}

/* server
int proc_msg_gen_resp(ra_samp_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_response_header_t **pp_msg_resp_full)
{
    //todo check input
    int ret = 0;
    FILE* OUTPUT = stdout;
    {
        // The ISV application sends msg0 to the SP.
        // The ISV decides whether to support this extended epid group id.
        fprintf(OUTPUT, "\nSending MSG %d to remote attestation service provider.\n", p_msg_full->type);

        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/", pp_ra_ctx,
            p_msg_full,
            pp_msg_resp_full);
        if (ret != 0)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
                "[%s].", __FUNCTION__);
        }
        fprintf(OUTPUT, "\nSent MSG %d to remote attestation service.\n", p_msg_full->type);
    }
    return ret;
}
*/

//int gen_msg1(sgx_enclave_id_t enclave_id, sgx_ra_context_t *context, ra_samp_request_header_t **pp_msg1_full)
int gen_msg1(sgx_enclave_id_t enclave_id, sgx_ra_context_t *context, ra_samp_msg1_request_header_t **pp_msg1_full, char *pub_key)
{
    //todo check input
    int ret = 0;
    ra_samp_request_header_t *p_msg1_full =  NULL;
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_status_t status = SGX_SUCCESS;
    FILE* OUTPUT = stdout;

    unsigned char *byteArray = makeByteArray(pub_key);

    sgx_ec256_public_t *pub_key1;
    pub_key1 =(sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));

    memcpy(&(pub_key1->gx), &byteArray[0], 32);
    memcpy(&(pub_key1->gy), &byteArray[32], 32);

    PRINT_BYTE_ARRAY(OUTPUT, pub_key1, sizeof(sgx_ec256_public_t));


    // Remote attestation will be initiated the ISV server challenges the ISV
    // app or if the ISV app detects it doesn't have the credentials
    // (shared secret) from a previous attestation required for secure
    // communication with the server.
    {
        // ISV application creates the ISV enclave.
        do
        {
            ret = enclave_init_ra(enclave_id,
                                  &status,
                                  false,
                                  context,
                                  pub_key1);
        //Ideally, this check would be around the full attestation flow.
        } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

        free(pub_key1);

        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        fprintf(OUTPUT, "\nCall enclave_init_ra success.");

        // isv application call uke sgx_ra_get_msg1
        p_msg1_full = (ra_samp_request_header_t*)
                      malloc(sizeof(ra_samp_request_header_t)
                             + sizeof(sgx_ra_msg1_t));
        if(NULL == p_msg1_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg1_full->type = TYPE_RA_MSG1;
        p_msg1_full->size = sizeof(sgx_ra_msg1_t);
        do
        {
            ret = sgx_ra_get_msg1(*context, enclave_id, sgx_ra_get_ga,
                                  (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                                  + sizeof(ra_samp_request_header_t)));
            if (ret == SGX_SUCCESS) break;
            sleep(3); // Wait 3s between retries
        } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
        if(SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        else
        {
            fprintf(OUTPUT, "\nCall sgx_ra_get_msg1 success.\n");

            fprintf(OUTPUT, "\nMSG1 body generated -\n");
            *pp_msg1_full = (ra_samp_msg1_request_header_t *) p_msg1_full;

            PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

        }
    }

CLEANUP:
    return ret;
}

int gen_msg3(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg1_response_header_t *p_msg2_full, ra_samp_msg3_request_header_t** pp_msg3_full, uint8_t *ias_crt, bool client_verify_ias, bool server_verify_ias, uint8_t *resp_crt, uint8_t
*resp_sign, uint8_t *resp_body)
//int gen_msg3(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_response_header_t *p_msg2_full, ra_samp_request_header_t** pp_msg3_full)
{
    int ret = 0;
    sgx_ra_msg3_t *p_msg3 = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t* p_msg3_full = NULL;

    sgx_ra_msg2_t* p_msg2_body = NULL;
    uint32_t msg3_size = 0;
    bool attestation_passed = true;
    sample_ra_att_result_msg_t * p_att_result_msg_body = NULL;

    FILE* OUTPUT = stdout;
        {
            // Successfully sent msg1 and received a msg2 back.
            // Time now to check msg2.
            if(TYPE_RA_MSG2 != p_msg2_full->type)
            {

                fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
                                "[%s].", __FUNCTION__);
            }

            fprintf(OUTPUT, "\nSent MSG1 to remote attestation service "
                            "provider. Received the following MSG2:\n");
            PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
                             sizeof(ra_samp_response_header_t)
                             + p_msg2_full->size);

            fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
            PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, (ra_samp_response_header_t *)p_msg2_full);
        }

        p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
                                      + sizeof(ra_samp_response_header_t));

        {
            busy_retry_time = 2;
            // The ISV app now calls uKE sgx_ra_proc_msg2,
            // The ISV app is responsible for freeing the returned p_msg3!!

            do
            {
                ret = sgx_ra_proc_msg2(context,
                                   enclave_id,
                                   sgx_ra_proc_msg2_trusted,
                                   sgx_ra_get_msg3_trusted,
                                   p_msg2_body,
                                   p_msg2_full->size,
                                   &p_msg3,
                                   &msg3_size);
            } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
            if(!p_msg3)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            if(SGX_SUCCESS != (sgx_status_t)ret)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "ret = 0x%08x [%s].", ret, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            else
            {
                fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
                fprintf(OUTPUT, "\nMSG3 - \n");
            }
        }
        PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);
        if(!client_verify_ias && server_verify_ias){
            fprintf(OUTPUT, "\n************ Calling IAS from server side ************\n");
            ias_att_report_t attestation_report = {0};
            ret = ias_verify_attestation_evidence(p_msg3->quote, NULL, &attestation_report, ias_crt, resp_crt, resp_sign, resp_body, false);
            if(0 != ret){
                ret = 3;
                fprintf(stderr,"\nError, IAS Call failed");
                goto CLEANUP;
            }
        }

        if(!client_verify_ias && !server_verify_ias){
            fprintf(OUTPUT, "\n************ Generating Fake Report************\n");
            ias_att_report_t attestation_report = {0};
            ret = ias_verify_attestation_evidence(p_msg3->quote, NULL, &attestation_report, ias_crt, resp_crt, resp_sign, resp_body, true);
            if(0 != ret){
                ret = 3;
                goto CLEANUP;
            }
        }

        p_msg3_full = (ra_samp_request_header_t*)malloc(
                       sizeof(ra_samp_request_header_t) + msg3_size);
        if(NULL == p_msg3_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg3_full->type = TYPE_RA_MSG3;
        p_msg3_full->size = msg3_size;
        if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
        {
            fprintf(OUTPUT,"\nError: INTERNAL ERROR - memcpy failed in [%s].",
                    __FUNCTION__);
            ret = -1;
            goto CLEANUP;
        }
        *pp_msg3_full = (ra_samp_msg3_request_header_t *) p_msg3_full;

CLEANUP:
    return ret;
}

int secret_encrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *sk_secret, size_t sk_secret_len, uint8_t *iv1, uint8_t *mac1, uint8_t *mk_secret, size_t mk_secret_len, uint8_t *iv2, uint8_t *mac2, uint8_t *project_id, size_t project_id_len)
{
    uint8_t *sealed_sk;
    uint8_t *sealed_secret;
    sealed_sk = NULL;
    sealed_secret = NULL;
    sealed_sk = (uint8_t *) malloc(sealed_len);
    size_t sealed_secret_len = get_sealed_data_len(enclave_id, 0, sk_secret_len);
    sealed_secret = (uint8_t *) malloc(sealed_secret_len);
    crypto_provision_kek(enclave_id, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, sealed_sk, sealed_len, project_id, project_id_len);

    crypto_provision_kek(enclave_id, sealed_sk, sealed_len, sk_secret, sk_secret_len, iv1, mac1, sealed_secret, sealed_secret_len, NULL, 0);

    crypto_transport_secret(enclave_id, sealed_mk, sealed_len, sealed_secret, sealed_secret_len, mk_secret, mk_secret_len, iv2, mac2, project_id, project_id_len);

    free(sealed_sk);
    free(sealed_secret);
    sealed_sk = NULL;
    sealed_secret = NULL;
    return 0;
}

int secret_decrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *mk_secret, size_t mk_secret_len, uint8_t *iv1, uint8_t *mac1, uint8_t *sk_secret, size_t sk_secret_len, uint8_t *iv2, uint8_t *mac2, uint8_t *project_id, size_t project_id_len)
{
    uint8_t *sealed_sk, *sealed_secret;
    sealed_sk = NULL;
    sealed_secret = NULL;
    sealed_sk = (uint8_t *) malloc(sealed_len);
    size_t sealed_secret_len = get_sealed_data_len(enclave_id, 0, mk_secret_len);
    sealed_secret = (uint8_t *) malloc(sealed_secret_len);

    crypto_provision_kek(enclave_id, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, sealed_sk, sealed_len, project_id, project_id_len);
    crypto_provision_kek(enclave_id, sealed_mk, sealed_len, mk_secret, mk_secret_len, iv1, mac1, sealed_secret, sealed_secret_len, project_id, project_id_len);
    crypto_transport_secret(enclave_id, sealed_sk, sealed_len, sealed_secret, sealed_secret_len, sk_secret, sk_secret_len, iv2, mac2, NULL, 0);

    free(sealed_sk);
    free(sealed_secret);
    sealed_sk = NULL;
    sealed_secret = NULL;
    return 0;
}

int get_kek(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *sk_kek, size_t sk_kek_len, uint8_t *iv1, uint8_t *mac1, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *project_id, size_t project_id_len)
{
    uint8_t *sealed_sk = (uint8_t *) malloc(sealed_len);

    crypto_provision_kek(enclave_id, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, sealed_sk, sealed_len, project_id, project_id_len);

    crypto_provision_kek(enclave_id, sealed_sk, sealed_len, sk_kek, sk_kek_len, iv1, mac1, sealed_kek, sealed_kek_len, NULL, 0);
    return 0;
}

int new_proc_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *dh_sk, size_t dh_sk_len, uint8_t *iv1, uint8_t *mac1)
{
    size_t sealed_len = get_sealed_data_len(enclave_id, 0, SK_KEY_SIZE);
    uint8_t *sealed_dh;
    sealed_dh = NULL;
    sealed_dh = (uint8_t *) malloc(sealed_len);
    uint8_t *sealed_sk;
    sealed_sk = NULL;
    sealed_sk = (uint8_t *) malloc(sealed_len);
    get_dh_key(enclave_id, context, p_att_result_msg_full, sealed_dh, sealed_len);

    size_t project_id_len = get_project_id_len(enclave_id, context, p_att_result_msg_full);
    uint8_t *project_id = (uint8_t *)malloc(project_id_len);
    get_project_id(enclave_id, context, p_att_result_msg_full, project_id);

    if(sealed_mk_len == 0 && mk_sk_len == 0)
    {
        fprintf(stdout, "\nGenerate new keys\n");
        crypto_generate_key(enclave_id, SK_KEY_SIZE, sealed_sk, sealed_len);
        sealed_mk_len = sealed_len;
        crypto_generate_key(enclave_id, SK_KEY_SIZE, sealed_mk, sealed_mk_len);
        crypto_transport_secret(enclave_id, sealed_mk, sealed_mk_len, sealed_sk, sealed_len, mk_sk, SK_KEY_SIZE, iv, mac, project_id, project_id_len);
    }
    else
    {
        crypto_provision_kek(enclave_id, sealed_mk, sealed_mk_len, mk_sk, mk_sk_len, iv, mac, sealed_sk, sealed_len, project_id, project_id_len);
    }
    crypto_transport_secret(enclave_id, sealed_dh, sealed_len, sealed_sk, sealed_len, dh_sk, SK_KEY_SIZE, iv1, mac1, NULL, 0);
    return 0;
}

int ma_proc_ra(sgx_enclave_id_t enclave_id, ra_samp_msg3_response_header_t* s_msg4, sgx_ra_context_t s_p_ctxt, ra_samp_msg3_request_header_t *c_msg3, void **c_p_net_ctxt, ra_samp_msg3_response_header_t **pp_resp2, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *ias_crt, bool client_verify_ias, int policy, uint8_t *attribute, size_t attribute_len, uint8_t *iv1, uint8_t *mac1)
{
    sgx_status_t status = SGX_SUCCESS;
    int ret = 0;
    sample_ra_att_result_msg_t *p_att_result_msg_body = NULL;
    uint8_t *mr_to_verify = NULL;
    size_t sealed_nonse_len = get_sealed_data_len(enclave_id, 0, SK_KEY_SIZE);

    proc_ra(enclave_id, s_p_ctxt, s_msg4, NULL, 0, NULL, 0);

    size_t project_id_len = get_project_id_len(enclave_id, s_p_ctxt, s_msg4);
    uint8_t *project_id = (uint8_t *)malloc(project_id_len);
    get_project_id(enclave_id, s_p_ctxt, s_msg4, project_id);

    ra_samp_request_header_t *c_msg3_full = (ra_samp_request_header_t *)c_msg3;
    sgx_ra_msg3_t *c_msg3_final = (sgx_ra_msg3_t*)((uint8_t*)c_msg3_full + sizeof(ra_samp_request_header_t));
    sgx_quote_t *c_msg3_p_quote = (sgx_quote_t *)c_msg3_final->quote;
    size_t c_msg3_p_quote_len = sizeof(sgx_quote_t);


    sample_ra_att_result_msg_t *s_msg4_body = NULL;
    sample_ra_att_result_msg_t *c_msg4_body = NULL;
    size_t c_msg4_body_len = sizeof(sample_ra_att_result_msg_t) + project_id_len;
    c_msg4_body = (sample_ra_att_result_msg_t *) malloc(c_msg4_body_len);
    s_msg4_body = (sample_ra_att_result_msg_t *)s_msg4->body;
    size_t s_msg4_body_len = sizeof(sample_ra_att_result_msg_t) + project_id_len;

    ret = ecall_proc_ma(enclave_id, &status, s_msg4_body, s_msg4_body_len, s_p_ctxt, c_msg3_p_quote, c_msg3_p_quote_len, c_p_net_ctxt, sealed_mk, sealed_mk_len, mk_sk, mk_sk_len, iv, mac, policy, attribute, attribute_len, iv1, mac1, c_msg4_body, c_msg4_body_len, project_id, project_id_len);

    set_enclave(c_p_net_ctxt, enclave_id);
    set_secret(c_p_net_ctxt, NULL, 0, NULL, 0);
    sp_ra_proc_msg3_req(c_p_net_ctxt, c_msg3_final, c_msg3_full->size, (ra_samp_response_header_t **)pp_resp2, NULL, project_id, NULL, ias_crt, client_verify_ias, c_msg4_body);
    free(project_id);
    free(c_msg4_body);

    return 0;
}
int get_mk_mr_list(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, uint8_t *sk_mr_list, size_t sk_mr_list_len, uint8_t *project_id, size_t project_id_len, uint8_t *mk_mr_list, size_t mk_mr_list_len, uint8_t *new_mk_mr_list, uint8_t *iv1, uint8_t *mac1, uint8_t *iv2, uint8_t *mac2, uint8_t *iv3, uint8_t *mac3, uint8_t *iv, uint8_t *mac)
{
    size_t sealed_sk_len = get_sealed_data_len(enclave_id, 0, SK_KEY_SIZE);
    uint8_t *sealed_sk = (uint8_t *)malloc(sealed_sk_len);
    //getting sealed sk from mk_sk
    crypto_provision_kek(enclave_id, sealed_mk, sealed_mk_len, mk_sk, SK_KEY_SIZE, iv1, mac1, sealed_sk, sealed_sk_len, project_id, project_id_len);
    if (mk_mr_list == NULL)
    {
        size_t sealed_mr_list_len = get_sealed_data_len(enclave_id, 0, sk_mr_list_len);
        uint8_t *sealed_mr_list = (uint8_t *)malloc(sealed_mr_list_len);
        //getting sealed_list from sk_list
        crypto_provision_kek(enclave_id, sealed_sk, sealed_sk_len, sk_mr_list, sk_mr_list_len, iv2, mac2, sealed_mr_list, sealed_mr_list_len, NULL, 0);
        size_t new_mk_mr_list_len = get_encrypted_len(enclave_id, sealed_mr_list, sealed_mr_list_len);
        //creating mk_list
        crypto_transport_secret(enclave_id, sealed_mk, sealed_mk_len, sealed_mr_list, sealed_mr_list_len, new_mk_mr_list, new_mk_mr_list_len, iv, mac, sealed_sk, sealed_sk_len);
    }
    else
    {
        char *mr_list1 = (char *)malloc(sk_mr_list_len);
        char *mr_list2 = (char *)malloc(mk_mr_list_len);
        //getting list from sk_list
        crypto_decrypt(enclave_id, sealed_sk, sealed_sk_len, mr_list1, sk_mr_list_len, sk_mr_list, iv2, mac2, NULL, 0);
        //getting list from sk_list
        crypto_decrypt(enclave_id, sealed_mk, sealed_mk_len, mr_list2, mk_mr_list_len, mk_mr_list, iv3, mac3, sealed_sk, sealed_sk_len);
        if(memcmp(mr_list1, mr_list2, 32) == 0)
        {
            size_t sealed_mr_list_len = get_sealed_data_len(enclave_id, 0, sk_mr_list_len);
            uint8_t *sealed_mr_list = (uint8_t *)malloc(sealed_mr_list_len);
            //getting sealed_list from sk_list
            crypto_provision_kek(enclave_id, sealed_sk, sealed_sk_len, sk_mr_list, sk_mr_list_len, iv2, mac2, sealed_mr_list, sealed_mr_list_len, NULL, 0);
            size_t new_mk_mr_list_len = get_encrypted_len(enclave_id, sealed_mr_list, sealed_mr_list_len);
            //creating mk_list
            crypto_transport_secret(enclave_id, sealed_mk, sealed_mk_len, sealed_mr_list, sealed_mr_list_len, new_mk_mr_list, new_mk_mr_list_len, iv, mac, sealed_sk, sealed_sk_len);
        }
        else
        {
            fprintf(stdout,"Owner MR Enclave miss-match");
            return -1;
        }

    }
    return 0;
}

int get_sk_data(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, uint8_t *mk_data, size_t mk_data_len, uint8_t *project_id, size_t project_id_len, uint8_t *sk_data, uint8_t *iv1, uint8_t *mac1, uint8_t *iv2, uint8_t *mac2, uint8_t *iv, uint8_t *mac)
{
    size_t sealed_sk_len = get_sealed_data_len(enclave_id, 0, SK_KEY_SIZE);
    uint8_t *sealed_sk = (uint8_t *)malloc(sealed_sk_len);
    //getting sealed_sk from mk_sk
    crypto_provision_kek(enclave_id, sealed_mk, sealed_mk_len, mk_sk, SK_KEY_SIZE, iv1, mac1, sealed_sk, sealed_sk_len, project_id, project_id_len);

    size_t sealed_data_len = get_sealed_data_len(enclave_id, 0, mk_data_len);
    uint8_t *sealed_data = (uint8_t *)malloc(sealed_data_len);
    crypto_provision_kek(enclave_id, sealed_mk, sealed_mk_len, mk_data, mk_data_len, iv2, mac2, sealed_data, sealed_data_len, sealed_sk, sealed_sk_len);

    size_t sk_data_len = get_encrypted_len(enclave_id, sealed_data, sealed_data_len);
    crypto_transport_secret(enclave_id, sealed_sk, sealed_sk_len, sealed_data, sealed_data_len, sk_data, sk_data_len, iv, mac, NULL, 0);

}

int proc_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_secret, size_t sealed_len, uint8_t *sealed_secret2, size_t secret2_len)
{
    int ret = 0;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t *p_msg3_full = NULL;

    sgx_ra_msg2_t *p_msg2_body = NULL;
    uint32_t msg3_size = 0;
    bool attestation_passed = true;
    sample_ra_att_result_msg_t *p_att_result_msg_body = NULL;

    FILE* OUTPUT = stdout;
        /*
        // The ISV application sends msg3 to the SP to get the attestation
        // result message, attestation result message needs to be freed when
        // no longer needed. The ISV service provider decides whether to use
        // linkable or unlinkable signatures. The format of the attestation
        // result is up to the service provider. This format is used for
        // demonstration.  Note that the attestation result message makes use
        // of both the MK for the MAC and the SK for the secret. These keys are
        // established from the SIGMA secure channel binding.
        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
                                      p_msg3_full,
                                      &p_att_result_msg_full);
        if(ret || !p_att_result_msg_full)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
            goto CLEANUP;
        }
        */


        p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                           + sizeof(ra_samp_response_header_t));
        if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
                            "received was NOT of type att_msg_result. Type = "
                            "%d. [%s].", p_att_result_msg_full->type,
                             __FUNCTION__);
            goto CLEANUP;
        }

        fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
        PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,
                         p_att_result_msg_full->size);

        // Check the MAC using MK on the attestation result message.
        // The format of the attestation result message is ISV specific.
        // This is a simple form for demonstration. In a real product,
        // the ISV may want to communicate more information.
        ret = verify_att_result_mac(enclave_id,
                &status,
                context,
                (uint8_t*)&p_att_result_msg_body->platform_info_blob,
                sizeof(ias_platform_info_blob_t),
                (uint8_t*)&p_att_result_msg_body->mac,
                sizeof(sgx_mac_t));
        if((SGX_SUCCESS != ret) ||
           (SGX_SUCCESS != status))
        {
            ret = -1;
            fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result "
                            "message MK based cmac failed in [%s].",
                            __FUNCTION__);
            goto CLEANUP;
        }

        // Check the attestation result for pass or fail.
        // Whether attestation passes or fails is a decision made by the ISV Server.
        // When the ISV server decides to trust the enclave, then it will return success.
        // When the ISV server decided to not trust the enclave, then it will return failure.
        if(0 != p_att_result_msg_full->status[0]
           || 0 != p_att_result_msg_full->status[1])
        {
            fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
                            "failed in [%s].", __FUNCTION__);
            attestation_passed = false;
        }

        // The attestation result message should contain a field for the Platform
        // Info Blob (PIB).  The PIB is returned by the IAS in the attestation report.
        // It is not returned in all cases, but when it is, the ISV app
        // should pass it to the blob analysis API called sgx_report_attestation_status()
        // along with the trust decision from the ISV server.
        // The ISV application will take action based on the update_info.
        // returned in update_info by the API.  
        // This call is stubbed out for the sample.
        // 
        // sgx_update_info_bit_t update_info;
        // ret = sgx_report_attestation_status(
        //     &p_att_result_msg_body->platform_info_blob,
        //     attestation_passed ? 0 : 1, &update_info);

        // Get the shared secret sent by the server using SK (if attestation
        // passed)
        //uint8_t *tmp_sealed_nonse;
        /*if(attestation_passed && p_att_result_msg_body->secret.payload_size != 0)
        {
            if (sealed_len == 0) {
                //Extract sealed nonse in tmp variable for comparison
                sealed_len = get_sealed_data_len(enclave_id, 0, 16);
                tmp_sealed_nonse = (uint8_t*)malloc(sealed_len);
                ret = client_put_secret_data(enclave_id,
                                      &status,
                                      context,
                                      p_att_result_msg_body->secret.payload,
                                      p_att_result_msg_body->secret.payload_size,
                                      p_att_result_msg_body->secret.payload_tag,
                                      tmp_sealed_nonse, sealed_len);
                //Compare extracted sealed nonse with the one received as input
                if (crypto_sealed_cmp(enclave_id, tmp_sealed_nonse, sealed_len, sealed_secret, sealed_len) != 0) {
                    fprintf(stdout,"\nNonse Comparision failed\n");
                    ret = -1;
                    goto CLEANUP;
                }
            }
            else {
                //Extract sealed nonse to be sent back as output
                ret = client_put_secret_data(enclave_id,
                                      &status,
                                      context,
                                      p_att_result_msg_body->secret.payload,
                                      p_att_result_msg_body->secret.payload_size,
                                      p_att_result_msg_body->secret.payload_tag,
                                      sealed_secret, sealed_len);
            }
            if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status)) {
                fprintf(OUTPUT, "\nError in retrieving sealed nonse from msg4\n");
                goto CLEANUP;
            }
        }*/
        if(p_att_result_msg_body->data1.payload_size == 16) {
            ret = client_put_secret_data(enclave_id,
                                  &status,
                                  context,
                                  p_att_result_msg_body->data1.payload,
                                  p_att_result_msg_body->data1.payload_size,
                                  p_att_result_msg_body->data1.payload_tag,
                                  sealed_secret2, secret2_len);


            if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status))
            {
                fprintf(OUTPUT, "\nError in retrieving sealed session key.\nError, attestation result message secret "
                                "using SK based AESGCM failed in [%s]. ret = "
                                "0x%0x. status = 0x%0x", __FUNCTION__, ret,
                                 status);
                goto CLEANUP;
            }
        }
        fprintf(OUTPUT, "\nSecret successfully received from server.\n");

CLEANUP:
    return ret;
}
int get_project_id_len(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full)
{
	uint32_t proj_id_len;
	sample_ra_att_result_msg_t *p_att_result_msg_body = NULL;
	p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                           + sizeof(ra_samp_response_header_t));

	proj_id_len = p_att_result_msg_body->project_id.payload_size;
	return proj_id_len;
}

int get_project_id(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *project_id)
{
	int ret = 0;
	uint32_t proj_id_len;
	sgx_status_t status = SGX_SUCCESS;
	sample_ra_att_result_msg_t *p_att_result_msg_body = NULL;

	p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)p_att_result_msg_full->body;
	proj_id_len = p_att_result_msg_body->project_id.payload_size;

	ret = server_get_project_id(enclave_id,
                                &status,
                                context,
                                p_att_result_msg_body->project_id.payload,
                                p_att_result_msg_body->project_id.payload_size,
                                p_att_result_msg_body->project_id.payload_tag,
                                project_id, proj_id_len);
	return ret;
}

int get_dh_key(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_dh, size_t sealed_len)
{
    int ret = 0;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t *p_msg3_full = NULL;

    sgx_ra_msg2_t *p_msg2_body = NULL;
    uint32_t msg3_size = 0;
    bool attestation_passed = true;
    sample_ra_att_result_msg_t *p_att_result_msg_body = NULL;

    FILE* OUTPUT = stdout;
        /*
        // The ISV application sends msg3 to the SP to get the attestation
        // result message, attestation result message needs to be freed when
        // no longer needed. The ISV service provider decides whether to use
        // linkable or unlinkable signatures. The format of the attestation
        // result is up to the service provider. This format is used for
        // demonstration.  Note that the attestation result message makes use
        // of both the MK for the MAC and the SK for the secret. These keys are
        // established from the SIGMA secure channel binding.
        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
                                      p_msg3_full,
                                      &p_att_result_msg_full);
        if(ret || !p_att_result_msg_full)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
            goto CLEANUP;
        }
        */


        p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                           + sizeof(ra_samp_response_header_t));
        if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
                            "received was NOT of type att_msg_result. Type = "
                            "%d. [%s].", p_att_result_msg_full->type,
                             __FUNCTION__);
            goto CLEANUP;
        }

        fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
        PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,
                         p_att_result_msg_full->size);

        // Check the MAC using MK on the attestation result message.
        // The format of the attestation result message is ISV specific.
        // This is a simple form for demonstration. In a real product,
        // the ISV may want to communicate more information.
        ret = verify_att_result_mac(enclave_id,
                &status,
                context,
                (uint8_t*)&p_att_result_msg_body->platform_info_blob,
                sizeof(ias_platform_info_blob_t),
                (uint8_t*)&p_att_result_msg_body->mac,
                sizeof(sgx_mac_t));
        if((SGX_SUCCESS != ret) ||
           (SGX_SUCCESS != status))
        {
            ret = -1;
            fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result "
                            "message MK based cmac failed in [%s].",
                            __FUNCTION__);
            goto CLEANUP;
        }

        // Check the attestation result for pass or fail.
        // Whether attestation passes or fails is a decision made by the ISV Server.
        // When the ISV server decides to trust the enclave, then it will return success.
        // When the ISV server decided to not trust the enclave, then it will return failure.
        if(0 != p_att_result_msg_full->status[0]
           || 0 != p_att_result_msg_full->status[1])
        {
            fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
                            "failed in [%s].", __FUNCTION__);
            attestation_passed = false;
        }

        // The attestation result message should contain a field for the Platform
        // Info Blob (PIB).  The PIB is returned by the IAS in the attestation report.
        // It is not returned in all cases, but when it is, the ISV app
        // should pass it to the blob analysis API called sgx_report_attestation_status()
        // along with the trust decision from the ISV server.
        // The ISV application will take action based on the update_info.
        // returned in update_info by the API.  
        // This call is stubbed out for the sample.
        // 
        // sgx_update_info_bit_t update_info;
        // ret = sgx_report_attestation_status(
        //     &p_att_result_msg_body->platform_info_blob,
        //     attestation_passed ? 0 : 1, &update_info);

        // Get the shared secret sent by the server using SK (if attestation
        // passed)
        if(attestation_passed)
        {
            ret = ecall_get_ra_dh_key(enclave_id,
                                  &status,
                                  context,
                                  sealed_dh, sealed_len);
            if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status))
            {
                fprintf(OUTPUT, "\nError, attestation result message secret "
                                "using SK based AESGCM failed in [%s]. ret = "
                                "0x%0x. status = 0x%0x", __FUNCTION__, ret,
                                 status);
                goto CLEANUP;
            }
            fprintf(OUTPUT, "\nSecret successfully received from server.\n");
            fprintf(OUTPUT, "\nRemote attestation success!\n");
        }

CLEANUP:
    return ret;
}

int close_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context)
{
    int ret;
    sgx_status_t status = SGX_SUCCESS;
    ret = enclave_ra_close(enclave_id, &status, context);
    if (SGX_SUCCESS != ret || status)
    {
        ret = enclave_ra_close(enclave_id, &status, context);
    }
    return ret;
}
