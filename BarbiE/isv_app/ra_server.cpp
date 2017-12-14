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
#include <stdbool.h>
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
#include "isv_app.h"
#include "ra_server.h"
#include "common.h"

int proc_msg_gen_resp(ra_samp_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_response_header_t **pp_msg_resp_full, ra_samp_request_header_t *c_p_msg_full, uint8_t *project_id, uint8_t *owner_mr_e, uint8_t *spid, uint8_t *ias_crt, bool client_verify_ias, sgx_ec256_private_t* priv_key)
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
            pp_msg_resp_full, c_p_msg_full, project_id, owner_mr_e, spid, ias_crt, client_verify_ias, priv_key);
        if (ret != 0)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
                "[%s].", __FUNCTION__);
        }
        fprintf(OUTPUT, "\nSent MSG %d to remote attestation service.\n", p_msg_full->type);
    }
    return ret;
}

int proc_msg0(ra_samp_msg0_request_header_t *p_msg_full, void **pp_ra_ctx, uint8_t *spid, bool client_verify_ias)
{
    sample_ra_msg0_t *p_msg0 = NULL;
    p_msg0 =  (sample_ra_msg0_t *)p_msg_full->body;
    if(!client_verify_ias)
    {
        return proc_msg_gen_resp((ra_samp_request_header_t *)p_msg_full, pp_ra_ctx, NULL, NULL, NULL, NULL, (uint8_t*)p_msg0->spid, NULL, false, NULL);
    }

    return proc_msg_gen_resp((ra_samp_request_header_t *)p_msg_full, pp_ra_ctx, NULL, NULL, NULL, NULL, spid, NULL, false, NULL);
}

int proc_msg1(ra_samp_msg1_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_msg1_response_header_t **pp_msg_resp_full, char* priv_key)
{
    sgx_ec256_private_t *priv_key1;
    int ret = 0;

    unsigned char *byteArray = makeByteArray(priv_key);
    priv_key1 =(sgx_ec256_private_t*) malloc(sizeof(sgx_ec256_private_t));
    memcpy(&(priv_key1->r), &byteArray[0], 32);

    ret = proc_msg_gen_resp((ra_samp_request_header_t *)p_msg_full, pp_ra_ctx, (ra_samp_response_header_t **)pp_msg_resp_full, NULL, NULL, NULL, NULL, NULL, false, priv_key1);

    free(priv_key1);
    return ret;
}

int proc_msg3(ra_samp_msg3_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_msg3_response_header_t **pp_msg_resp_full, ra_samp_msg3_request_header_t *c_p_msg_full, uint8_t *project_id, uint8_t *owner_mr_e, uint8_t *ias_crt, bool client_verify_ias)
{
    return proc_msg_gen_resp((ra_samp_request_header_t *)p_msg_full, pp_ra_ctx, (ra_samp_response_header_t **)pp_msg_resp_full, (ra_samp_request_header_t *)c_p_msg_full, project_id, owner_mr_e, NULL, ias_crt, client_verify_ias, NULL);
}

int get_sk(void **pp_ra_ctx, uint8_t *plain_sk, size_t sk_len, uint8_t *enc_sk, uint8_t *sk_iv, uint8_t *sk_mac) {
    return sp_get_sk(pp_ra_ctx, plain_sk, sk_len, enc_sk, sk_iv, sk_mac);
}

uint8_t *get_mr_e(ra_samp_msg3_request_header_t *p_msg3)
{
    return sp_get_mr_e((sgx_ra_msg3_t*)((uint8_t*)p_msg3 +
            sizeof(ra_samp_request_header_t)));
}

uint8_t *get_mr_s(ra_samp_msg3_request_header_t *p_msg3)
{
    return sp_get_mr_s((sgx_ra_msg3_t*)((uint8_t*)p_msg3 +
            sizeof(ra_samp_request_header_t)));
}
