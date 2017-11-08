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

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server.  Refer to Intel IAS documentation for
// communication between the ISV Application Server and Intel's IAS (Intel
// Attestation Server).


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

// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "isv_enclave_u.h"

#include "sgx_tseal.h"
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
#include "common.h"
#include "ra_client.h"
#include "ra_server.h"

int test();

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x
int main(int argc, char* argv[])
{
    return test();
}

int test()
{
    int ret = 0;
    uint8_t secret[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    size_t sealed_len = 0, plain_len = 0, add_mac_len = 0;
    uint8_t *sealed_secret;
    sgx_enclave_id_t enclave_id;
    sgx_ra_context_t context;
    void *p_ra_ctx = NULL;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg1_resp_full = NULL;
    ra_samp_request_header_t *p_msg3_full = NULL;
    ra_samp_response_header_t *p_msg3_resp_full = NULL;
    ret = gen_msg0((ra_samp_msg0_request_header_t **)&p_msg0_full, NULL);
    ret = proc_msg0((ra_samp_msg0_request_header_t *)p_msg0_full, &p_ra_ctx, NULL, false);
    ret = initialize_enclave(&enclave_id);
    sealed_len = get_sealed_data_len(enclave_id, 0, sizeof(secret));
    sealed_secret = (uint8_t*) malloc(sealed_len);
    ret = gen_msg1(enclave_id, &context, (ra_samp_msg1_request_header_t **)&p_msg1_full);
    ret = proc_msg1((ra_samp_msg1_request_header_t *)p_msg1_full, &p_ra_ctx, (ra_samp_msg1_response_header_t **)&p_msg1_resp_full);
    ret = set_secret(&p_ra_ctx, &secret[0], sizeof(secret));
    //ret = set_secret(&p_ra_ctx, sealed_secret, sealed_len);
    ret = set_enclave(&p_ra_ctx, enclave_id);
    ret = gen_msg3(enclave_id, context, (ra_samp_msg1_response_header_t *)p_msg1_resp_full, (ra_samp_msg3_request_header_t **)&p_msg3_full, NULL, false, false, NULL, NULL, NULL);
    ret = proc_msg3((ra_samp_msg3_request_header_t *)p_msg3_full, &p_ra_ctx, (ra_samp_msg3_response_header_t **)&p_msg3_resp_full, NULL, NULL, false);
    ret = proc_ra(enclave_id, context, (ra_samp_msg3_response_header_t *)p_msg3_resp_full, sealed_secret, sealed_len);
    ret = close_ra(enclave_id, context);
    add_mac_len = get_add_mac_len(enclave_id, sealed_secret, sealed_len);
    plain_len = get_encrypted_len(enclave_id, sealed_secret, sealed_len);
    destroy_enclave(enclave_id);

    ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg1_resp_full);
    ra_free_network_response_buffer(p_msg3_resp_full);

    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);
    SAFE_FREE(sealed_secret);
    printf("\nEnter a character before exit ...\n");
    getchar();
    return 0;
}

